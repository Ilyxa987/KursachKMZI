from tinyec import registry
import secrets
import hashlib
import math
from Crypto.Util.number import GCD, inverse
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def int_from_bytes(b):
    return int.from_bytes(b, 'big')

def hash_message(m, curve_n):
    return int_from_bytes(hashlib.sha256(m).digest()) % curve_n

def bytes_to_int(b):
    return int.from_bytes(b, 'big')

def int_to_bytes(x):
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

class GroupManager:
    def __init__(self, n, t):
        self.n = n
        self.t = t
        self.L = {}           # BIi2 -> (Xi, BIi1, node_id, xi)
        self.revoked = set()
        self.curve = None
        self.G = None
        self.p = None
        self.gs = None
        self.gx = None
        self.alpha = None
        self.Mx = None
        self.m = []
        self.M = 1
        self.hash_func = hash_message
        self.registered_yi = {}   # BIi2 -> yi

    def generate_elliptic_curve(self):
        curve = registry.get_curve("secp256r1")
        self.curve = curve
        self.G = curve.g
        self.p = curve.field.n

    def generate_group_keys(self):
        self.gs = secrets.randbelow(self.p)
        self.gx = self.gs * self.G
        self.alpha = secrets.randbelow(self.p)
        self.Mx = self.alpha * self.G

    def generate_crt_parameters(self):
        self.m = []
        while len(self.m) < self.n:
            mi = secrets.randbits(64)
            if mi > 0 and all(GCD(mi, x) == 1 for x in self.m):
                self.m.append(mi)
        self.M = 1
        for i in range(self.t):
            self.M *= self.m[i]

    def register(self, node_id):
        # Шаг 1-4
        r = secrets.randbelow(self.p)
        R = r * self.G
        H = self.hash_func(node_id.encode(), self.p)
        xr = R.x
        BIi1 = (xr + self.alpha) * H + r
        BIi1 %= self.p

        left = BIi1 * self.G
        right = (xr * self.G + self.Mx) * H + R
        if left != right:
            raise ValueError("Ошибка аутентификации на шаге 2")

        xi = secrets.randbelow(self.p)
        Xi = xi * self.G
        u = secrets.randbelow(self.p)
        U = u * self.G
        xu = U.x
        BIi2 = (xu + xi) * H + u
        BIi2 %= self.p

        left2 = BIi2 * self.G
        right2 = (xu * self.G + Xi) * H + U
        if left2 != right2:
            raise ValueError("Ошибка аутентификации на шаге 4")

        self.L[BIi2] = (Xi, BIi1, node_id, xi)   # сохраняем xi

        # Вычисляем yi
        active = [b for b in self.L.keys() if b not in self.revoked]
        Ji = (BIi2 * self.M) % self.p
        if len(active) < self.t:
            yi = secrets.randbelow(self.p)
        elif len(active) == self.t:
            # Суммируем по всем, кроме текущего
            s = 0
            for b in active:
                if b == BIi2:
                    continue
                J = (b * self.M) % self.p
                y = self.registered_yi.get(b, 0)
                s = (s + J * y) % self.p
            needed = (self.gs - s) % self.p
            yi = needed * inverse(Ji, self.p) % self.p
        else:
            # Участников больше t – для простоты случайный (в реальности требуется обновление)
            yi = secrets.randbelow(self.p)

        self.registered_yi[BIi2] = yi
        si = (xi + yi) % self.p
        Si = si * self.G
        return si, BIi2, BIi1, Xi, Si

    def revoke(self, BIi2):
        """Отзыв участника и перевыпуск ключей для всех оставшихся"""
        if BIi2 not in self.L:
            return {}
        self.revoked.add(BIi2)
        # Определяем активных участников
        active = [b for b in self.L.keys() if b not in self.revoked]
        # Устанавливаем n = количество активных (или оставляем старый n? Для CRT нужно не менее t)
        self.n = len(active)
        # Генерируем новые CRT параметры
        self.generate_crt_parameters()
        # Перевычисляем yi для всех активных участников
        new_yi = {}
        # Для первых t-1 – случайные
        for i, b in enumerate(active):
            if i < self.t - 1:
                new_yi[b] = secrets.randbelow(self.p)
        # Для t-го (если есть) – подгоняем сумму
        if len(active) >= self.t:
            # Найдём сумму для первых t-1
            s = 0
            for b in active[:self.t-1]:
                J = (b * self.M) % self.p
                y = new_yi[b]
                s = (s + J * y) % self.p
            last_b = active[self.t-1]
            J_last = (last_b * self.M) % self.p
            needed = (self.gs - s) % self.p
            new_yi[last_b] = needed * inverse(J_last, self.p) % self.p
            # Для остальных (если active > t) – случайные
            for b in active[self.t:]:
                new_yi[b] = secrets.randbelow(self.p)
        else:
            # Если активных меньше t – все случайные
            for b in active:
                new_yi[b] = secrets.randbelow(self.p)

        # Обновляем registered_yi
        self.registered_yi = new_yi
        # Формируем обновления для узлов: (new_si, new_Si)
        updates = {}
        for b in active:
            Xi, BIi1, node_id, xi = self.L[b]
            yi = self.registered_yi[b]
            new_si = (xi + yi) % self.p
            new_Si = new_si * self.G
            updates[b] = (new_si, new_Si)
        return updates

    def is_revoked(self, BIi2):
        return BIi2 in self.revoked

    def get_member_info(self, BIi2):
        info = self.L.get(BIi2)
        if info:
            Xi, BIi1, node_id, xi = info
            return (Xi, BIi1, BIi2, node_id)
        return None


class IoTNode:
    def __init__(self, gm, node_id, tsg_public_key=None):
        self.gm = gm
        self.G = gm.G
        self.p = gm.p
        self.node_id = node_id
        self.tsg_pubkey = tsg_public_key
        self.si, self.BIi2, self.BIi1, self.Xi, self.Si = gm.register(node_id)
        print(f"{node_id} зарегистрирован. BIi2={self.BIi2}")

    def update_key(self, new_si, new_Si):
        self.si = new_si
        self.Si = new_Si

    def encrypt_bi_for_tsg(self, bi):
        if self.tsg_pubkey is None:
            return bi
        cipher = PKCS1_OAEP.new(self.tsg_pubkey)
        bi_bytes = int_to_bytes(bi)
        return cipher.encrypt(bi_bytes)

    def generate_partial_signature(self, message):
        gamma = secrets.randbelow(self.p)
        theta = gamma * self.G
        x_theta = theta.x
        mu = self.gm.hash_func(message, self.p)
        M = self.gm.M
        Ji = (self.BIi2 * M) % self.p
        sigma = (gamma * x_theta - mu * self.si * Ji) % self.p
        encrypted_bi = self.encrypt_bi_for_tsg(self.BIi2)
        return {
            'theta': theta,
            'sigma': sigma,
            'encrypted_bi': encrypted_bi,
            'BIi2': self.BIi2,
            'si': self.si,
            'Si': self.Si,
            'Xi': self.Xi
        }


class TSG:
    def __init__(self, gm, private_key=None):
        self.gm = gm
        self.G = gm.G
        self.p = gm.p
        self.SL = []
        self.rsa_private_key = private_key

    def decrypt_bi(self, encrypted_bi):
        if self.rsa_private_key is None:
            return encrypted_bi
        cipher = PKCS1_OAEP.new(self.rsa_private_key)
        bi_bytes = cipher.decrypt(encrypted_bi)
        return bytes_to_int(bi_bytes)

    def verify_partial(self, part, message):
        BIi2 = self.decrypt_bi(part['encrypted_bi'])
        if self.gm.is_revoked(BIi2):
            print(f"  Участник с BIi2={BIi2} отозван, подпись отклонена")
            return False
        theta = part['theta']
        sigma = part['sigma']
        Si = part['Si']
        mu = self.gm.hash_func(message, self.p)
        M = self.gm.M
        Ji = (BIi2 * M) % self.p
        left = sigma * self.G + mu * (Si * Ji)
        right = theta * theta.x
        return left == right

    def aggregate(self, parts, message):
        if len(parts) < self.gm.t:
            raise Exception(f"Недостаточно подписей: нужно {self.gm.t}, получено {len(parts)}")
        Theta_point = None
        Sigma = 0
        Omega = None
        valid_parts = []
        for part in parts:
            if not self.verify_partial(part, message):
                print("Частичная подпись не прошла проверку")
                continue
            valid_parts.append(part)
            theta = part['theta']
            sigma = part['sigma']
            BIi2 = self.decrypt_bi(part['encrypted_bi'])
            Xi = part['Xi']
            Ji = (BIi2 * self.gm.M) % self.p
            term_theta = theta * theta.x
            if Theta_point is None:
                Theta_point = term_theta
            else:
                Theta_point = Theta_point + term_theta
            Sigma = (Sigma + sigma) % self.p
            term_omega = Xi * Ji
            if Omega is None:
                Omega = term_omega
            else:
                Omega = Omega + term_omega
            self.SL.append((theta, sigma, BIi2))
        if len(valid_parts) < self.gm.t:
            raise Exception(f"Недостаточно валидных частичных подписей: нужно {self.gm.t}, получено {len(valid_parts)}")
        return Theta_point, Sigma, Omega, valid_parts

    def verify_final(self, Theta_point, Sigma, Omega, message):
        mu = self.gm.hash_func(message, self.p)
        left = Sigma * self.G + mu * (self.gm.gx + Omega)
        return left == Theta_point

    def open_signature(self):
        ids = []
        for (_, _, BIi2) in self.SL:
            if not self.gm.is_revoked(BIi2):
                info = self.gm.get_member_info(BIi2)
                if info:
                    _, _, _, node_id = info
                    ids.append(node_id)
        return ids


def generate_rsa_keypair():
    key = RSA.generate(2048)
    return key.publickey(), key

def test_full_scheme():
    print("=== 1. ИНИЦИАЛИЗАЦИЯ СИСТЕМЫ ===")
    gm = GroupManager(n=3, t=2)
    gm.generate_elliptic_curve()
    gm.generate_group_keys()
    gm.generate_crt_parameters()
    print(f"Групповой публичный ключ gx = {gm.gx}")
    print(f"CRT параметры m_i = {gm.m}, M = {gm.M}")

    tsg_pubkey, tsg_privkey = generate_rsa_keypair()

    print("\n=== 2. РЕГИСТРАЦИЯ УЧАСТНИКОВ ===")
    node1 = IoTNode(gm, "device_1", tsg_pubkey)
    node2 = IoTNode(gm, "device_2", tsg_pubkey)
    node3 = IoTNode(gm, "device_3 ", tsg_pubkey)

    tsg = TSG(gm, private_key=tsg_privkey)

    print("\n=== 3. ФОРМИРОВАНИЕ ПОДПИСИ (device_1 + device_2) ===")
    message = b"Temperature = 42C"
    parts = [
        node1.generate_partial_signature(message),
        node2.generate_partial_signature(message)
    ]

    print("Проверка частичных подписей:")
    for i, p in enumerate(parts):
        valid = tsg.verify_partial(p, message)
        print(f"  Подпись {i+1}: {'верна' if valid else 'неверна'}")

    print("\n=== 4. АГРЕГАЦИЯ ПОРОГОВОЙ ПОДПИСИ ===")
    try:
        Theta, Sigma, Omega, used_parts = tsg.aggregate(parts, message)
        print(f"Θ (точка) = {Theta}")
        print(f"Σ (скаляр) = {Sigma}")
        print(f"Ω (точка) = {Omega}")
    except Exception as e:
        print(f"Ошибка агрегации: {e}")
        return

    print("\n=== 5. ПРОВЕРКА ИТОГОВОЙ ПОДПИСИ ===")
    valid_final = tsg.verify_final(Theta, Sigma, Omega, message)
    print(f"Итоговая подпись {'верна' if valid_final else 'неверна'}")

    print("\n=== 6. РАСКРЫТИЕ ПОДПИСИ ===")
    print("Реальные ID участников:", tsg.open_signature())

    print("\n=== 7. ОТЗЫВ УЧАСТНИКА device_2 ===")
    bi2_to_revoke = node2.BIi2
    updates = gm.revoke(bi2_to_revoke)   # перевыпуск ключей
    # Применяем обновления к узлам
    if updates:
        for bi2, (new_si, new_Si) in updates.items():
            if bi2 == node1.BIi2:
                node1.update_key(new_si, new_Si)
            elif bi2 == node3.BIi2:
                node3.update_key(new_si, new_Si)
    print(f"Участник device_2 (BIi2={bi2_to_revoke}) отозван и ключи перевыпущены")

    print("\n=== 8. ПОПЫТКА ПОДПИСИ С ОТОЗВАННЫМ УЧАСТНИКОМ (device_1 + device_2) ===")
    part_revoked = node2.generate_partial_signature(message)
    parts_with_revoked = [
        node1.generate_partial_signature(message),
        part_revoked
    ]
    try:
        Theta2, Sigma2, Omega2, _ = tsg.aggregate(parts_with_revoked, message)
        valid2 = tsg.verify_final(Theta2, Sigma2, Omega2, message)
        print(f"Подпись с отозванным участником: {'верна' if valid2 else 'неверна'}")
    except Exception as e:
        print(f"Ошибка агрегации (ожидаемо): {e}")

    print("\n=== 9. ПОДПИСЬ ДВУМЯ ОСТАВШИМИСЯ (device_1 + device_3) ===")
    parts_valid = [
        node1.generate_partial_signature(message),
        node3.generate_partial_signature(message)
    ]
    try:
        Theta3, Sigma3, Omega3, _ = tsg.aggregate(parts_valid, message)
        valid3 = tsg.verify_final(Theta3, Sigma3, Omega3, message)
        print(f"Подпись device_1 + device_3: {'верна' if valid3 else 'неверна'}")
    except Exception as e:
        print(f"Ошибка агрегации: {e}")

    print("\n=== 10. ПРОВЕРКА ПОРОГА ===")
    try:
        tsg.aggregate([node1.generate_partial_signature(message)], message)
    except Exception as e:
        print(f"Порог сработал: {e}")

if __name__ == "__main__":
    test_full_scheme()