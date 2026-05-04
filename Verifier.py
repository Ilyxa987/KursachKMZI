from GM import hash_message


class Verifier:
    def __init__(self, G, I, gx):
        self.G = G
        self.I = I
        self.gx = gx

    @staticmethod
    def Aggregate(partial_sigs, I):
        """Агрегирует частичные подписи.
        Возвращает Theta, Sigma, Omega, список участников и количество.
        """
        Theta = None
        participants = []
        curve_order = I   # порядок кривой (n)
        for ps in partial_sigs:
            r = ps["theta"].x % curve_order
            term = ps["theta"] * r
            Theta = term if Theta is None else Theta + term

        Sigma = sum(ps["sigma"] for ps in partial_sigs) % curve_order

        Omega = None
        for ps in partial_sigs:
            term = ps["X"] * ps["J"]
            Omega = term if Omega is None else Omega + term
            participants.append(ps["node_id"])

        return Theta, Sigma, Omega, participants, len(partial_sigs)

    def VerifySign(self, theta, sigma, Omega, m, count, participants, revoked_set):
        """
        Проверяет групповую подпись.
        Возвращает True, если подпись валидна и ни один участник не отозван.
        """
        for pid in participants:
            if pid in revoked_set:
                return False

        mu = hash_message(m, self.I)
        left = (sigma * self.G) + (mu * (count * self.gx + Omega))
        return left == theta