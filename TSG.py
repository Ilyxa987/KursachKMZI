import tinyec
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
        mu = hash_message(message, self.PKtsg)

        for ps in partial_signatures:
            theta_i = ps["theta"]
            sigma_i = ps["sigma"]
            CipherBI2 = ps["CipherBI2"]
            X_i = ps["X"]
            S_i = ps["S"]

            if self.VerifyPartSignature(theta_i, sigma_i, CipherBI2, X_i, S_i, message):
                BIi2 = self.DecryptAnonIdentificator(CipherBI2)
                J_i = (BIi2 * self.M) % self.I

                verified_signatures.append({
                    "theta": theta_i,
                    "sigma": sigma_i,
                    "J": J_i,
                    "X": X_i,
                    "BIi2": BIi2
                })
            else:
                print("Частичная подпись отклонена")

        if len(verified_signatures) == 0:
            print("Нет корректных подписей")
            return None

        Theta = None
        for vs in verified_signatures:
            term = (vs["theta"] * vs["theta"].x) % self.I
            if Theta is None:
                Theta = term
            else:
                Theta += term

        Sigma = sum(vs["sigma"] for vs in verified_signatures)

        Omega = None
        for vs in verified_signatures:
            term = vs["X"] * vs["J"]
            if Omega is None:
                Omega = term
            else:
                Omega += term

        self.AddToSL(verified_signatures, Theta, Sigma)

        return (Theta, Sigma, Omega)

    def AddToSL(self, verified_signatures: list, Theta, Sigma):
        if not hasattr(self, "SL"):
            self.SL = []

        for vs in verified_signatures:
            entry = {
                "theta": vs["theta"],
                "sigma": vs["sigma"],
                "BIi2": vs["BIi2"],
                "Theta": Theta,
                "Sigma": Sigma
            }
            self.SL.append(entry)




