from GM import hash_message


class Verifier:
    def __init__(self, G, I, gx):
        self.G = G
        self.I = I
        self.gx = gx

    def VerifySign(self, theta, sigma, Omega, m, count):
        mu = hash_message(m, self.I)
        # Формула верификации для суммы подписей:
        # sigma*G + mu*(count*gx + sum_X) == sum_theta
        left = (sigma * self.G) + (mu * (count * self.gx + Omega))

        print(f"LEFT:  {left}")
        print(f"RIGHT: {theta}")

        return left == theta
