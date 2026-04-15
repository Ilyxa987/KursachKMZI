from GM import GroupManager
from IoT import IoT
from TSG import TSG
from Verifyer import Verifier

gm = None
IoTs = []
tsg = None
ver = None


def InitGM(n, t):
    gm = GroupManager(n, t)
    gm.GenerateElepticCurve()
    gm.GenerateGMKeys()
    gm.GenerateGroupKeys()
    return gm


def Register(gm: GroupManager, ID: int):
    if gm.CheckID(ID):
        print("Новый ID. Начинаем регистрацию")
    else:
        print("Устройство уже зарегистрировано")
        return
    a, b, G, gx, M, Mx, I = gm.GetOpens()
    IoTs[ID].setOpens(a, b, G, gx, M, Mx, I)
    R, BI1 = gm.FirstAnonimization(ID)
    if IoTs[ID].VerifyBI1(R, BI1):
        print("Первая аутентификация успешна")
    else:
        print("Первая аутентификация неуспешна")
        return
    IoTs[ID].GenerateFirstPartKey()
    U, BI2 = IoTs[ID].secondAnonimization(gm.getmi(ID))
    X, _, _ = IoTs[ID].getParams()
    if gm.VerifyBI2(U, BI2, X, BI1):
        print("Вторая аутентификация успешна")
    else:
        print("Вторая аутентификация неуспешна")
        return
    gm.addMember(ID, X, BI1, BI2)
    y = gm.generateSecondPartKey(ID)
    IoTs[ID].generateKey(y)
    print("Ключ IoT сгенерирован")


def checkGS2(t, M, gs, G):
    sigma = 0
    omega = 0
    theta = 0
    for i in range(t):
        s, o, th = IoTs[i].checkpartSign()
        sigma += s
        omega += o
        if i == 0:
            theta = th
        else:
            theta += th
    theta = theta % M
    sign = (sigma + 71231234 * (gs + omega)) % M
    print(sign * G, theta * G)
    

print("Стенд групповой подписи IoT-устройств")

while True:
    print("1 - Инициализировать систему")
    print("2 - Зарегистрировать IoT-устройство")
    print("3 - Сгенерировать часть подписи")
    print("d - Запустить все")
    mode = input()
    if mode == '1':
        print("Введите n и t")
        n, t = map(int, input().split())
        gm = InitGM(n, t)
        for i in range(n):
            IoTs.append(IoT(i))

    elif mode == '2':
        print("Введите ID устройства")
        ID = int(input())
        Register(gm, ID)

    elif mode == '3':
        tsg = TSG()
        a, b, G, gx, M, Mx, I = gm.GetOpens()
        tsg.set_curve_params(G, I)
        tsg.set_group_params(gx, M)
        print("TSG создан")
        PK, Ntsg = tsg.getPK()
        m = b"Hello"
        print(f"Сообщение: {m}")
        parts = []
        for i in range(3):
            parts.append(IoTs[i].generatePartSignature(m, PK, Ntsg))

    elif mode == 'd':
        print("Введите n и t")
        #n, t = map(int, input().split())
        n, t = 5, 3
        gm = InitGM(n, t)
        for i in range(n):
            IoTs.append(IoT(i))
        for i in range(t):
            Register(gm, i)
        tsg = TSG()
        a, b, G, gx, M, Mx, I = gm.GetOpens()
        tsg.set_curve_params(G, I)
        tsg.set_group_params(gx, M)
        print("TSG создан")
        PK, Ntsg = tsg.getPK()
        m = b"Hello"
        print(f"Сообщение: {m}")
        parts = []
        checks = None
        Omega = None
        Theta = None
        for i in range(t):
            theta, sigma, encrypted_BI2 = IoTs[i].generatePartSignature(m, PK, Ntsg)
            x = IoTs[i].getx()
            S = IoTs[i].getS()
            parts.append({'theta': theta, 'sigma': sigma, 'CipherBI2': encrypted_BI2, 'X': x, 'S': S})
        # checkGS2(t, M, gm.getgs(), G)
        Theta, Sigma, Omega = tsg.PublicSignature(parts, m)
        print("Подпись создана")
        ver = Verifier()
        ver.set_public_params(a, b, G, gx, I)
        print(ver.checkGS2(Theta, Sigma, Omega, m, gm.getgs(), M))
        # print(ver.VerifySign(Theta, Sigma, Omega, m))

    else:
        break
