from tinyec import registry
import secrets
import hashlib
import math
from Crypto.Util.number import GCD


def int_from_bytes(b):
    return int.from_bytes(b, 'big')


def hash_message(m, curve_n):
    return int_from_bytes(hashlib.sha256(m).digest()) % curve_n


class GroupManager:
    def __init__(self, n, t):
        self.n = n
        self.t = t
        self.L = {}                     # BIi2 -> (Xi, BIi1, BIi2, node_id)
        self.revoked = set()            # множество отозванных BIi2
        self.curve = None
        self.G = None
        self.n_curve = None
        self.gs = None
        self.gx = None
        self.alpha = None
        self.Mx = None
        self.m = []
        self.M = 1
        self.hash_func = hash_message

    def generate_elliptic_curve(self):
        curve = registry.get_curve("secp256r1")
        self.curve = curve
        self.G = curve.g
        self.n_curve = curve.field.n

    def generate_group_keys(self):
        self.gs = secrets.randbelow(self.n_curve)
        self.gx = self.gs * self.G
        self.alpha = secrets.randbelow(self.n_curve)
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
        r = secrets.randbelow(self.n_curve)
        R = r * self.G
        H = self.hash_func(node_id.encode(), self.n_curve)
        xr = R.x
        BIi1 = (xr + self.alpha) * H + r
        BIi1 %= self.n_curve

        left = BIi1 * self.G
        right = (xr * self.G + self.Mx) * H + R
        if left != right:
            raise ValueError("Ошибка аутентификации на шаге 2")

        xi = secrets.randbelow(self.n_curve)
        Xi = xi * self.G
        u = secrets.randbelow(self.n_curve)
        U = u * self.G
        xu = U.x
        BIi2 = (xu + xi) * H + u
        BIi2 %= self.n_curve

        left2 = BIi2 * self.G
        right2 = (xu * self.G + Xi) * H + U
        if left2 != right2:
            raise ValueError("Ошибка аутентификации на шаге 4")

        self.L[BIi2] = (Xi, BIi1, BIi2, node_id)

        yi = secrets.randbelow(self.n_curve)
        si = (xi + yi) % self.n_curve
        Si = si * self.G

        return si, BIi2, BIi1, Xi, Si

    def revoke(self, BIi2):
        if BIi2 in self.L:
            print(f"Revoking member with BIi2={BIi2}")
            self.revoked.add(BIi2)
            del self.L[BIi2]
            # Пересчёт CRT параметров (в демо-целях, но ключи остальных не обновляются)
            self.generate_crt_parameters()
        else:
            print(f"Участник с BIi2={BIi2} не найден")

    def is_revoked(self, BIi2):
        return BIi2 in self.revoked

    def get_member_info(self, BIi2):
        return self.L.get(BIi2, None)


class IoTNode:
    def __init__(self, gm, node_id):
        self.gm = gm
        self.G = gm.G
        self.n = gm.n_curve
        self.node_id = node_id
        self.si, self.BIi2, self.BIi1, self.Xi, self.Si = gm.register(node_id)
        print(f"{node_id} зарегистрирован. BIi2={self.BIi2}")

    def generate_partial_signature(self, message, tsg_public_key=None):
        gamma = secrets.randbelow(self.n)
        theta = gamma * self.G
        x_theta = theta.x
        mu = self.gm.hash_func(message, self.n)
        M = self.gm.M
        Ji = (self.BIi2 * M) % self.n
        sigma = (gamma * x_theta - mu * self.si * Ji) % self.n
        if tsg_public_key is None:
            encrypted_bi = self.BIi2
        else:
            encrypted_bi = self.BIi2 ^ hash_message(str(tsg_public_key).encode(), self.n)
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
        self.n = gm.n_curve
        self.SL = []
        self.private_key = private_key

    def decrypt_bi(self, encrypted_bi):
        if self.private_key is None:
            return encrypted_bi
        return encrypted_bi ^ hash_message(str(self.private_key).encode(), self.n)

    def verify_partial(self, part, message):
        BIi2 = self.decrypt_bi(part['encrypted_bi'])
        if self.gm.is_revoked(BIi2):
            print(f"  Участник с BIi2={BIi2} отозван, подпись отклонена")
            return False

        theta = part['theta']
        sigma = part['sigma']
        Si = part['Si']
        mu = self.gm.hash_func(message, self.n)
        M = self.gm.M
        Ji = (BIi2 * M) % self.n
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
            Si = part['Si']
            Ji = (BIi2 * self.gm.M) % self.n

            term_theta = theta * theta.x
            if Theta_point is None:
                Theta_point = term_theta
            else:
                Theta_point = Theta_point + term_theta

            Sigma = (Sigma + sigma) % self.n

            term_omega = Si * Ji
            if Omega is None:
                Omega = term_omega
            else:
                Omega = Omega + term_omega

            self.SL.append((theta, sigma, BIi2))

        # КРИТИЧЕСКАЯ ПРОВЕРКА: валидных подписей должно быть не меньше t
        if len(valid_parts) < self.gm.t:
            raise Exception(f"Недостаточно валидных частичных подписей: нужно {self.gm.t}, получено {len(valid_parts)}")

        if Theta_point is None:
            raise Exception("Нет валидных частичных подписей")

        return Theta_point, Sigma, Omega, valid_parts

    # Для демо-целей используем упрощённую проверку (без gx)
    def verify_final(self, Theta_point, Sigma, Omega, message):
        mu = self.gm.hash_func(message, self.n)
        left = Sigma * self.G + mu * Omega
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


def test_full_scheme():
    print("=== 1. ИНИЦИАЛИЗАЦИЯ СИСТЕМЫ ===")
    gm = GroupManager(n=3, t=2)
    gm.generate_elliptic_curve()
    gm.generate_group_keys()
    gm.generate_crt_parameters()
    print(f"Групповой публичный ключ gx = {gm.gx}")
    print(f"CRT параметры m_i = {gm.m}, M = {gm.M}")

    print("\n=== 2. РЕГИСТРАЦИЯ УЧАСТНИКОВ ===")
    node1 = IoTNode(gm, "device_1")
    node2 = IoTNode(gm, "device_2")
    node3 = IoTNode(gm, "device_3")

    tsg = TSG(gm, private_key=12345)

    print("\n=== 3. ФОРМИРОВАНИЕ ПОДПИСИ (device_1 + device_2) ===")
    message = b"Temperature = 42C"
    parts = [
        node1.generate_partial_signature(message, tsg.private_key),
        node2.generate_partial_signature(message, tsg.private_key)
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
    gm.revoke(bi2_to_revoke)
    print(f"Участник device_2 (BIi2={bi2_to_revoke}) отозван")

    print("\n=== 8. ПОПЫТКА ПОДПИСИ С ОТОЗВАННЫМ УЧАСТНИКОМ (device_1 + device_2) ===")
    part_revoked = node2.generate_partial_signature(message, tsg.private_key)
    parts_with_revoked = [
        node1.generate_partial_signature(message, tsg.private_key),
        part_revoked
    ]
    try:
        Theta2, Sigma2, Omega2, _ = tsg.aggregate(parts_with_revoked, message)
        valid2 = tsg.verify_final(Theta2, Sigma2, Omega2, message)
        print(f"Подпись с отозванным участником: {'верна' if valid2 else 'неверна'}")
    except Exception as e:
        print(f"Ошибка агрегации (ожидаемо, так как подпись отозванного отклонена): {e}")

    print("\n=== 9. ПОДПИСЬ ДВУМЯ ОСТАВШИМИСЯ (device_1 + device_3) ===")
    parts_valid = [
        node1.generate_partial_signature(message, tsg.private_key),
        node3.generate_partial_signature(message, tsg.private_key)
    ]
    try:
        Theta3, Sigma3, Omega3, _ = tsg.aggregate(parts_valid, message)
        valid3 = tsg.verify_final(Theta3, Sigma3, Omega3, message)
        print(f"Подпись device_1 + device_3: {'верна' if valid3 else 'неверна'}")
    except Exception as e:
        print(f"Ошибка агрегации: {e}")

    print("\n=== 10. ПРОВЕРКА ПОРОГА ===")
    try:
        tsg.aggregate([node1.generate_partial_signature(message, tsg.private_key)], message)
    except Exception as e:
        print(f"Порог сработал: {e}")


if __name__ == "__main__":
    test_full_scheme()