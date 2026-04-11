from GM import GroupManager
from IoT import IoT

gm = None
IoTs = []

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
    U, BI2 = IoTs[ID].secondAnonimization()
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
    

print("Стенд групповой подписи IoT-устройств")

while True:
    print("1 - Инициализировать систему")
    print("2 - Зарегистрировать IoT-устройство")
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

    else:
        break
