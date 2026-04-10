from Crypto.PublicKey import RSA

class TSG:
    PKtsg: int # Открытый ключ TSG
    SKtsg: int # Закрытый ключ TSG
    Ntsg: int # Модуль RSA
    SL: list # Список подписей

    def __init__(self):
        private_key = RSA.generate(2048)
        public_key = private_key.public_key()
        self.Ntsg = public_key.n
        self.PKtsg = public_key.e
        self.SKtsg = private_key.d