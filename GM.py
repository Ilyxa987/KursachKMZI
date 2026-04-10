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
    n: int  # Количество IoT
    t: int  # Пороговое количество IoT
    p: int  # Модуль поля Fp
    a: int  # Коэффициент a
    b: int  # Коэффициент b
    G: tinyec.ec.Point  # Базовая точка
    Ms: int  # Закрытый ключ GM
    Mx: tinyec.ec.Point  # Закрытый ключ GM
    m: list  # Массив взаимно простых чисел
    M: int  # Произведение t m-ок
    gs: int  # Закрытый ключ группы
    gx: tinyec.ec.Point  # Открытый ключ группы

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
