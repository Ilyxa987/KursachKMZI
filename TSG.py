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
        # Theta = Σ (theta_i * r_i)
        Theta = None
        for ps in partial_sigs:
            r = ps["theta"].x % self.I
            term = ps["theta"] * r
            Theta = term if Theta is None else Theta + term

        Sigma = sum(ps["sigma"] for ps in partial_sigs) % self.I

        # Omega = Σ (X_i * J_i)
        Omega = None
        for ps in partial_sigs:
            term = ps["X"] * ps["J"]
            Omega = term if Omega is None else Omega + term

        return Theta, Sigma, Omega, len(partial_sigs)