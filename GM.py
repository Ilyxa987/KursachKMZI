from tinyec import registry
import tinyec
import random
from Crypto.Util.number import getPrime
from Crypto.Util.number import GCD
import secrets
import hashlib
import math

# Класс GM
class GroupManager:

    n: int # Количество IoT
    t: int # Пороговое количество IoT
    p: int # Модуль поля Fp
    a: int # Коэффициент a
    b: int # Коэффициент b
    G: tinyec.ec.Point # Базовая точка
    Ms: int # Закрытый ключ GM
    Mx: tinyec.ec.Point # Закрытый ключ GM
    m: list # Массив взаимопростых чисел
    M: int # Произведение t m-ок
    gs: int # Закрытый ключ группы
    gx: tinyec.ec.Point # Открытый ключ группы

    def __init__(self, n: int, t: int):
        if t >= n:
            print("Порог неверный")
            exit(1)
        self.n = n
        self.t = t

    def GenerateElepticCurve(self):
        curve = registry.get_curve("secp256r1")
        self.p = curve.field.p
        self.a = curve.a
        self.b = curve.b
        self.G = curve.g

    def GenerateGMKeys(self):
        self.Ms = random.randint(1, self.p)
        self.Mx = self.Ms * self.G
    
    def GenerateGroupKeys(self):
        self.m = []
        while len(self.m) != self.n:
            mi = secrets.randbits(128)
            if len(self.m) == 0:
                self.m.append(mi)
            for i in range(len(self.m)):
                if GCD(mi, self.m[i]) != 1:
                    continue
                elif i == len(self.m) - 1:
                    self.m.append(mi)
        self.M = math.prod(self.m[:self.t])
        self.gs = random.randint(1, self.p)
        self.gx = self.gs * self.G
    

class Iot:

    def __init__(self, G, p, si, BIi2, M):
        self.G = G
        self.p = p
        self.si = si        # приватный ключ
        self.BIi2 = BIi2    # анонимный ID
        self.M = M          # произведение m_i

        self.theta = None
        self.sigma = None

    def _hash(self, message: bytes):
        return int.from_bytes(hashlib.sha256(message).digest(), 'big') % self.p

    def GeneratePartSignature(self, message: bytes):
        # 1. γi
        gamma_i = secrets.randbelow(self.p)

        # 2. θi = γi * G
        self.theta = gamma_i * self.G
        x_theta = self.theta.x

        # 3. μ = h(m)
        mu = self._hash(message)

        # 4. Ji = BIi2 * M
        Ji = (self.BIi2 * self.M) % self.p

        # 5. σi = γi * xθi − μ * si * Ji mod p
        self.sigma = (gamma_i * x_theta - mu * self.si * Ji) % self.p

    def SendPartSignature(self):
        if self.theta is None or self.sigma is None:
            raise ValueError("Call GeneratePartSignature() first")

        return {
            "theta": self.theta,
            "sigma": self.sigma,
            "BIi2": self.BIi2,
            "BIi2_encrypted": self._encrypt_identity()
        }

    # псевдо-шифрование (заглушка для статьи)
    def _encrypt_identity(self):
        rnd = secrets.token_bytes(16)
        data = rnd + self.BIi2.to_bytes(32, 'big')
        return hashlib.sha256(data).hexdigest()


def test():
    print("=== INIT GM ===")
    gm = GroupManager(n=5, t=3)
    gm.GenerateElepticCurve()
    gm.GenerateGMKeys()
    gm.GenerateGroupKeys()

    print("p:", gm.p)
    print("M:", gm.M)

    # создаём IoT участника
    si = random.randint(1, gm.p)
    BIi2 = random.randint(1, gm.p)

    IoT = Iot(
        G=gm.G,
        p=gm.p,
        si=si,
        BIi2=BIi2,
        M=gm.M
    )

    message = b"Hello IoT Threshold Signature"

    print("\n=== GENERATE PARTIAL SIGNATURE ===")
    IoT.GeneratePartSignature(message)

    sig = IoT.SendPartSignature()

    print("Theta:", sig["theta"])
    print("Sigma:", sig["sigma"])
    print("BIi2:", sig["BIi2"])
    print("Encrypted BIi2:", sig["BIi2_encrypted"])


if __name__ == "__main__":
    test()