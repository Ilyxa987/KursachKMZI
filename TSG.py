from Crypto.PublicKey import RSA


class TSG:
    def __init__(self):
        key = RSA.generate(2048)
        self.PK = (key.e, key.n)
        self.SK = key.d

    def set_params(self, G, I, gx):
        self.G = G
        self.I = I
        self.gx = gx

    def Aggregate(self, partial_sigs, message):
        # Агрегация суммирует параметры всех участников
        sum_theta = partial_sigs[0]["theta"]
        for ps in partial_sigs[1:]:
            sum_theta += ps["theta"]

        sum_sigma = sum(ps["sigma"] for ps in partial_sigs) % self.I

        sum_X = partial_sigs[0]["X"]
        for ps in partial_sigs[1:]:
            sum_X += ps["X"]

        return sum_theta, sum_sigma, sum_X, len(partial_sigs)
