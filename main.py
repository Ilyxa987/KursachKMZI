from GM import GroupManager
from IoT import IoT
from TSG import TSG

gm = None
IoTs = []
tsg = None

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

def GeneratePartSignature():
    pass
    

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
            parts.append(IoTs[i].generatePartSignature(m, M, PK, Ntsg))
        
    
    elif mode == 'd':
        print("Введите n и t")
        n, t = map(int, input().split())
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
        for i in range(3):
            parts.append(IoTs[i].generatePartSignature(m, M, PK, Ntsg))
        print(parts)
        

    else:
        break
