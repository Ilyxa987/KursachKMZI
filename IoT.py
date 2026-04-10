from tinyec import registry
import secrets
import hashlib
import math
from Crypto.Util.number import GCD


# =======================
# Group Manager (GM)
# =======================
class GroupManager:
    """
    Менеджер группы (trusted center):

    Отвечает за:
    - инициализацию параметров системы
    - регистрацию участников
    - хранение соответствия BIi2 -> реальный ID
    - отзыв участников
    """

    def __init__(self, n, t):
        self.n = n          # всего участников
        self.t = t          # порог
        self.L = {}         # BIi2 -> ID

    def GenerateElepticCurve(self):
        """
        Инициализация эллиптической кривой (ECC)
        """
        curve = registry.get_curve("secp256r1")
        self.curve = curve
        self.G = curve.g
        self.n_curve = curve.field.n

    def GenerateKeys(self):
        """
        Генерация CRT параметров (m_i и M)
        Используется для threshold механизма
        """
        self.m = []
        while len(self.m) < self.n:
            mi = secrets.randbits(64)
            if mi > 0 and all(GCD(mi, x) == 1 for x in self.m):
                self.m.append(mi)

        self.M = math.prod(self.m[:self.t])

    def Register(self, ID):
        """
        Регистрация устройства:
        - выдаётся приватный ключ si
        - создаётся анонимный идентификатор BIi2
        """
        si = secrets.randbelow(self.n_curve)
        BIi2 = secrets.randbelow(self.n_curve)

        self.L[BIi2] = ID
        return si, BIi2

    def Revoke(self, BIi2):
        """
        Отзыв участника:
        - удаляем из списка
        - пересчитываем параметры системы
        """
        if BIi2 in self.L:
            print(f"Revoking: {self.L[BIi2]}")
            del self.L[BIi2]

            # пересчёт параметров (как в статье)
            self.GenerateKeys()

    def GetID(self, BIi2):
        return self.L.get(BIi2, None)

    def hash(self, m):
        return int.from_bytes(hashlib.sha256(m).digest(), 'big') % self.n_curve


# =======================
# IoT Node
# =======================
class Iot:
    """
    IoT устройство:

    - хранит приватный ключ
    - имеет анонимный идентификатор
    - умеет генерировать частичную подпись
    """

    def __init__(self, gm, ID):
        self.gm = gm
        self.G = gm.G
        self.n = gm.n_curve

        self.ID = ID
        self.si, self.BIi2 = gm.Register(ID)

        print(f"{ID} registered")

    def GeneratePartSignature(self, message):
        """
        Генерация частичной подписи:

        θ = γG
        σ = γ*xθ − μ * si * Ji
        """
        gamma = secrets.randbelow(self.n)

        theta = gamma * self.G
        mu = self.gm.hash(message)

        Ji = (self.BIi2 * self.gm.M) % self.n

        sigma = (gamma * theta.x - mu * self.si * Ji) % self.n

        return {
            "theta": theta,
            "sigma": sigma,
            "BIi2": self.BIi2,
            "si": self.si
        }


# =======================
# TSG (агрегатор подписей)
# =======================
class TSG:
    """
    Threshold Signature Generator:

    - проверяет partial подписи
    - собирает итоговую подпись
    - проверяет итоговую подпись
    - раскрывает участников
    """

    def __init__(self, gm):
        self.gm = gm
        self.G = gm.G
        self.n = gm.n_curve

    def VerifyPartial(self, part, message):
        """
        Проверка частичной подписи:

        σG + μSiJi == θ * xθ
        """
        theta = part["theta"]
        sigma = part["sigma"]
        BIi2 = part["BIi2"]
        si = part["si"]

        mu = self.gm.hash(message)
        Ji = (BIi2 * self.gm.M) % self.n

        left = sigma * self.G + mu * (si * self.G) * Ji
        right = theta.x * theta

        return left == right

    def Aggregate(self, parts):
        """
        Агрегация подписей:

        Θ = Σ θi * xθi
        Σ = Σ σi
        Ω = Σ Ji * Si
        """
        if len(parts) < self.gm.t:
            raise Exception("Not enough participants for threshold signature")

        Theta = None
        Sigma = 0
        Omega = None

        for part in parts:
            theta = part["theta"]
            sigma = part["sigma"]
            BIi2 = part["BIi2"]
            si = part["si"]

            Ji = (BIi2 * self.gm.M) % self.n

            # Θ
            term_theta = theta.x * theta
            Theta = term_theta if Theta is None else Theta + term_theta

            # Σ
            Sigma = (Sigma + sigma) % self.n

            # Ω
            Si = si * self.G
            term_omega = Ji * Si
            Omega = term_omega if Omega is None else Omega + term_omega

        return Theta, Sigma, Omega, parts

    def VerifyFinal(self, Theta, Sigma, Omega, message):
        """
        Проверка итоговой подписи:

        ΣG + μΩ == Θ
        """
        mu = self.gm.hash(message)
        return (Sigma * self.G + mu * Omega) == Theta

    def OpenSignature(self, parts):
        """
        Раскрытие подписи:
        возвращает реальные ID участников
        """
        ids = []
        for part in parts:
            BIi2 = part["BIi2"]
            ids.append(self.gm.GetID(BIi2))
        return ids


# =======================
# TEST (полный сценарий)
# =======================
def test():
    print("=== INIT SYSTEM ===")

    gm = GroupManager(3, 2)
    gm.GenerateElepticCurve()
    gm.GenerateKeys()

    # создаём устройства
    iot1 = Iot(gm, "device_1")
    iot2 = Iot(gm, "device_2")
    iot3 = Iot(gm, "device_3")

    tsg = TSG(gm)

    # сообщение
    message = b"Temperature = 42C"

    print("\n=== SEND SIGNED MESSAGE ===")
    print("Sender: device_1")
    print("Message:", message)

    # partial подписи (t = 2)
    p1 = iot1.GeneratePartSignature(message)
    p2 = iot2.GeneratePartSignature(message)

    print("\n=== PARTIAL SIGNATURES ===")
    print("Partial1:", tsg.VerifyPartial(p1, message))
    print("Partial2:", tsg.VerifyPartial(p2, message))

    print("\n=== AGGREGATION ===")
    Theta, Sigma, Omega, parts = tsg.Aggregate([p1, p2])

    print("Final valid:", tsg.VerifyFinal(Theta, Sigma, Omega, message))

    print("\n=== OPEN SIGNATURE ===")
    print("Signers:", tsg.OpenSignature(parts))

    print("\n=== REVOCATION ===")

    # отзыв второго
    gm.Revoke(p2["BIi2"])

    print("Trying signature after revoke...")

    try:
        p3 = iot3.GeneratePartSignature(message)

        # используем отозванного + нового
        Theta, Sigma, Omega, parts = tsg.Aggregate([p2, p3])

        print("Valid after revoke:", tsg.VerifyFinal(Theta, Sigma, Omega, message))
    except Exception as e:
        print("Error:", e)

    print("\n=== THRESHOLD TEST ===")

    try:
        # меньше порога
        tsg.Aggregate([p1])
    except Exception as e:
        print("Threshold check works:", e)


if __name__ == "__main__":
    test()