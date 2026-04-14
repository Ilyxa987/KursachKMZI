from Crypto.PublicKey import RSA
from GM import hash_message


class TSG:
    PKtsg: int # Открытый ключ TSG
    SKtsg: int # Закрытый ключ TSG
    Ntsg: int # Модуль RSA
    SL: list # Список подписей
    private_key: RSA.RsaKey
    public_key: RSA.RsaKey

    def __init__(self):
        private_key = RSA.generate(2048)
        public_key = private_key.public_key()
        self.Ntsg = public_key.n
        self.PKtsg = public_key.e
        self.SKtsg = private_key.d

    def getPK(self):
        return self.PKtsg

    def set_curve_params(self, G: tinyec.ec.Point, I: int):
        self.G = G
        self.I = I

    def set_group_params(self, gx: tinyec.ec.Point, M: int):
        self.gx = gx
        self.M = M
    
    def DecryptAnonIdentificator(self, CipherBI2: int):
        BI2 = pow(CipherBI2, self.SKtsg, self.Ntsg)
        return BI2

    def VerifyPartSignature(self, theta_i: tinyec.ec.Point, sigma_i: int,
                           CipherBI2: int, X_i: tinyec.ec.Point,
                           S_i: tinyec.ec.Point, message: bytes):
        BIi2 = self.DecryptAnonIdentificator(CipherBI2)
        mu = hash_message(message, self.PKtsg)
        J_i = (BIi2 * self.M) % self.I
        left = (sigma_i * self.G) + (mu * S_i * J_i)
        right = theta_i * theta_i.x
        return left == right

    def PublicSignature(self, partial_signatures: list, message: bytes):
        if len(partial_signatures) < 1:
            print("Ошибка: нет частичных подписей для агрегации")
            return None
        verified_signatures = []
        # ToDo




