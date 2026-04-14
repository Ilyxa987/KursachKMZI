from GM import GroupManager
from IoT import IoT
from TSG import TSG
from Verifyer import *

# 1. Инициализация GM
gm = GroupManager(n=5, t=3)
gm.GenerateElepticCurve()
gm.GenerateGMKeys()
gm.GenerateGroupKeys()
G, gx, M, Mx, I = gm.GetOpens()

# 2. Инициализация TSG
tsg = TSG()
tsg.set_params(G, I, gx)
PK, N = tsg.PK

# 3. Регистрация двух IoT устройств
ids = [101, 102]
device_list = []
for node_id in ids:
    device = IoT(node_id)
    device.setOpens(G, gx, M, Mx, I)

    # Этап 1
    R, BI1 = gm.FirstAnonimization(node_id)
    if device.VerifyBI1(R, BI1):
        # Этап 2
        device.GenerateFirstPartKey()
        U, BI2 = device.secondAnonimization()
        gm.addMember(node_id, device.X, BI1, BI2)

        # ✅ Генерация ключа с правильным y
        y = gm.generateSecondPartKey(node_id)
        device.generateKey(y)
        device_list.append(device)

# 4. Подпись сообщения всеми устройствами
msg = "Test Message"
p_sigs = [d.generatePartSignature(msg, PK, N) for d in device_list]

# 5. Агрегация и проверка
Theta, Sigma, Omega, count = tsg.Aggregate(p_sigs, msg)
v = Verifier(G, I, gx)

if v.VerifySign(Theta, Sigma, Omega, msg, count):
    print("\n[УСПЕХ] Групповая подпись подтверждена!")
else:
    print("\n[ОШИБКА] Подпись не валидна.")