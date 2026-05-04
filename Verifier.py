from GM import hash_message


class Verifier:
    def __init__(self, G, I, gx):
        self.G = G
        self.I = I
        self.gx = gx

    @staticmethod
    def Aggregate(partial_sigs, I, threshold):
        Theta = None
        participants = []
        for ps in partial_sigs:
            r = ps["theta"].x % I
            term = ps["theta"] * r
            Theta = term if Theta is None else Theta + term

        Sigma = sum(ps["sigma"] for ps in partial_sigs) % I

        Omega = None
        for ps in partial_sigs:
            term = ps["X"] * ps["J"]
            Omega = term if Omega is None else Omega + term
            participants.append(ps["node_id"])

        count = len(partial_sigs)
        if count < threshold:
            print(f"Агрегация невозможна: участников {count}, порог {threshold}")
            return None, None, None, [], 0

        return Theta, Sigma, Omega, participants, count

    def VerifySign(self, theta, sigma, Omega, m, count, participants, revoked_set):
        for pid in participants:
            if pid in revoked_set:
                return False

        mu = hash_message(m, self.I)
        left = (sigma * self.G) + (mu * (count * self.gx + Omega))
        return left == theta