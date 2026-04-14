import tinyec
import hashlib
import secrets
from GM import int_from_bytes, hash_message


class IoT:

    a: int # Коэффициент a
    b: int # Коэффициент b
    G: tinyec.ec.Point # Базовая точка
    Mx: tinyec.ec.Point # Закрытый ключ GM
    M: int # Произведение t m-ок
    gx: tinyec.ec.Point # Открытый ключ группы
    I: int
    x: int # Первая часть закрытого ключа
    X: tinyec.ec.Point # Вторая часть открытого ключа
    BI1: int # Первый анонимный идентификатор
    BI2: int # Второй анонимный идентификатор
    s: int # Закрытый ключ
    S: tinyec.ec.Point # Закрытый ключ

    def __init__(self, node_id):
        self.node_id = node_id
        print(f"Создано IoT-устройство с ID:{node_id}")

    def setOpens(self, a, b, G, gx, M, Mx, I):
        self.a = a
        self.b = b
        self.G = G
        self.gx = gx
        self.M = M
        self.Mx = Mx
        self.I = I

    def VerifyBI1(self, R, BI1):
        left = BI1 * self.G
        id = self.node_id.to_bytes()
        right = (R.x * self.G + self.Mx) * hash_message(id, self.I) + R
        if left == right:
            self.BI1 = BI1
            return True
        else:
            return False
        
    def GenerateFirstPartKey(self):
        self.x = secrets.randbelow(self.I)
        self.X = self.x * self.G
    
    def secondAnonimization(self):
        u = secrets.randbelow(self.I)
        U = u * self.G
        id = self.BI1.to_bytes(((len(bin(self.BI1)) - 2) // 8) + 1)
        BI2 = ((U.x + self.x) * hash_message(id, self.I) + u) % self.I
        self.BI2 = BI2
        return U, BI2
    
    def getParams(self):
        return self.X, self.BI1, self.BI2
    
    def generateKey(self, y):
        self.s = self.x + y
        self.S = self.s * self.G

    def generatePartSignature(self, m, M):
        mu = hash_message(m, self.I)
        J_i = (self.BI2 * M) % self.I
        gamma_i = secrets.randbelow(self.I)
        theta_i = gamma_i * self.G
        sigma_i = (gamma_i * theta_i.x - mu * self.s * J_i) % self.I
        # ToDo: encrypted_BI2
        encrypted_BI2 = None
        return theta_i, sigma_i, encrypted_BI2



