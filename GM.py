from tinyec import registry
import tinyec
import random
from Crypto.Util.number import getPrime
from Crypto.Util.number import GCD
import secrets
import hashlib
import math

def int_from_bytes(b):
    return int.from_bytes(b, 'big')

def hash_message(m, curve_n):
    return int_from_bytes(hashlib.sha256(m).digest()) % curve_n

# Класс GM
class GroupManager:

    n: int # Количество IoT
    t: int # Пороговое количество IoT
    p: int # Модуль поля Fp
    I: int # Порядок базовой точки
    a: int # Коэффициент a
    b: int # Коэффициент b
    G: tinyec.ec.Point # Базовая точка
    Ms: int # Закрытый ключ GM
    Mx: tinyec.ec.Point # Закрытый ключ GM
    m: list # Массив взаимопростых чисел
    M: int # Произведение t m-ок
    gs: int # Закрытый ключ группы
    gx: tinyec.ec.Point # Открытый ключ группы
    iots: dict # Список устройств

    def __init__(self, n: int, t: int):
        if t >= n:
            print("Порог неверный")
            exit(1)
        self.n = n
        self.t = t
        self.iots = {}

    def GenerateElepticCurve(self):
        curve = registry.get_curve("secp256r1")
        self.p = curve.field.p
        self.a = curve.a
        self.b = curve.b
        self.G = curve.g
        self.I = curve.field.n

    def GenerateGMKeys(self):
        self.Ms = secrets.randbelow(self.I)
        self.Mx = self.Ms * self.G

    def GenerateGroupKeys(self):
        self.m = []
        while len(self.m) < self.n:
            mi = secrets.randbits(64)
            if mi > 0 and all(GCD(mi, x) == 1 for x in self.m):
                self.m.append(mi)
        self.M = 1
        for i in range(self.t):
            self.M *= self.m[i]
        self.gs = secrets.randbelow(self.I)
        self.gx = self.gs * self.G

    def GetOpens(self):
        return self.a, self.b, self.G, self.gx, self.M, self.Mx, self.I

    def CheckID(self, ID: int):
        if ID not in self.iots.keys():
            return True
        else:
            return False
        
    def FirstAnonimization(self, ID: int):
        r = secrets.randbelow(self.I)
        R = r * self.G
        ID = ID.to_bytes()
        H = hash_message(ID, self.I)
        BI1 = ((R.x + self.Ms) * H + r) % self.I
        return R, BI1
    
    def VerifyBI2(self, U, BI2, X, BI1: int):
        left = BI2 * self.G
        id = BI1.to_bytes(((len(bin(BI1)) - 2) // 8) + 1)
        right = (U.x * self.G + X) * hash_message(id, self.I) + U
        if left == right:
            return True
        else:
            return False
        
    def addMember(self, ID, X, BI1, BI2):
        self.iots[ID] = [X, BI1, BI2]
    
    def generateSecondPartKey(self, ID):
        mi = self.m[ID]
        lam = pow(self.M // mi, -1, mi)
        b = self.gs % mi
        BI2 = self.iots[ID][2]
        y = (lam * b) * pow(mi * BI2, -1, self.I)
        return y

    
