import tinyec
import hashlib
import secrets
from GM import int_from_bytes, hash_message


class IoT:
    a: int  # Коэффициент a
    b: int  # Коэффициент b
    G: tinyec.ec.Point  # Базовая точка
    Mx: tinyec.ec.Point  # Закрытый ключ GM
    M: int  # Произведение t m-ок
    gx: tinyec.ec.Point  # Открытый ключ группы
    I: int
    x: int  # Первая часть закрытого ключа
    X: tinyec.ec.Point  # Вторая часть открытого ключа
    BI1: int  # Первый анонимный идентификатор
    BI2: int  # Второй анонимный идентификатор
    s: int  # Закрытый ключ
    S: tinyec.ec.Point  # Закрытый ключ
    gamma: int

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

    def secondAnonimization(self, mi):
        id = self.BI1.to_bytes(((len(bin(self.BI1)) - 2) // 8) + 1)
        while True:
            try:
                u = secrets.randbelow(self.I)
                U = u * self.G
                BI2 = ((U.x + self.x) * hash_message(id, self.I) + u) % self.I
                f = pow(BI2, -1, self.M)
                break
            except:
                continue
        self.BI2 = BI2
        return U, BI2

    def getParams(self):
        return self.X, self.BI1, self.BI2

    def generateKey(self, y):
        self.s = (self.x + y)
        self.S = self.s * self.G

    def getx(self):
        return self.x

    def getX(self):
        return self.X

    def getS(self):
        Si = (self.s * self.BI2) % self.M
        return Si

    def generatePartSignature(self, m, PK, N):
        mu = hash_message(m, self.I)
        # J_i = (self.BI2 * M) # Возможна ошибка
        J_i = self.BI2
        gamma_i = secrets.randbelow(self.I)
        theta_i = gamma_i * self.G
        x = theta_i.x

        encrypted_BI2 = pow(self.BI2, PK, N)

        sigma_i = (mu * self.s * J_i) % self.M
        sigma_i = (gamma_i * x - sigma_i)
        theta_i = gamma_i * x

        return theta_i, sigma_i, encrypted_BI2

    def checkKey(self):
        J_i = self.BI2
        return ((self.s - self.x) * J_i) % self.M

    def checkpartSign(self):
        J_i = self.BI2
        gamma = self.gamma
        theta = gamma * self.G
        x = theta.x
        sigma = (71231234 * self.s * J_i) % self.M
        sigma = (gamma * x - sigma)
        omega = (self.x * J_i) % self.M
        theta = gamma * x * self.G
        return sigma, omega, theta

    def checkSign(self):
        J_i = self.BI2
        selfsign = (self.s * J_i) % self.M
        gamma = self.gamma % self.I
        theta = gamma * self.G
        x = theta.x % self.I
        selfsign = (gamma * x - selfsign) % self.I
        check = (self.x * J_i) % self.M
        check = check * self.G
        theta = theta * x
        return selfsign, check, theta
