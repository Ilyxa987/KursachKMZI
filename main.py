from tinyec import registry
import tinyec
import random

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

    def __init__(self, n: int, t: int):
        if t >= n:
            Exception("Порог неверный")
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


gm = GroupManager(5, 3)
gm.GenerateElepticCurve()
gm.GenerateGMKeys()

