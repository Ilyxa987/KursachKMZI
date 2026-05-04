from GM import GroupManager
from IoT import IoT
from Verifier import Verifier

# 1. Инициализация GM
gm = GroupManager(n=5, t=3)
gm.GenerateElepticCurve()
gm.GenerateGMKeys()
gm.GenerateGroupKeys()
G, gx, M, Mx, I = gm.GetOpens()

# 2. Создаём верификатор
verifier = Verifier(G, I, gx)

# 3. Регистрируем три устройства
ids = [101, 102, 103]
devices = []
for node_id in ids:
    device = IoT(node_id)
    device.setOpens(G, gx, M, Mx, I)

    R, BI1 = gm.FirstAnonimization(node_id)
    if device.VerifyBI1(R, BI1):
        device.GenerateFirstPartKey()
        U, BI2 = device.secondAnonimization()
        gm.addMember(node_id, device.X, BI1, BI2)

        y = gm.generateSecondPartKey(node_id)
        device.generateKey(y)
        devices.append(device)
        print(f"Устройство {node_id} зарегистрировано.")

# 4. Подписываем сообщение ВСЕМИ устройствами
msg = "Test Message"
partial_sigs_all = [d.generatePartSignature(msg) for d in devices]

Theta, Sigma, Omega, participants, count = Verifier.Aggregate(partial_sigs_all, I)
valid = verifier.VerifySign(Theta, Sigma, Omega, msg, count, participants, gm.revoked)
print(f"\nПодпись всех устройств валидна: {valid}")

# 5. Отзываем устройство 102
gm.revokeMember(102)
print(f"Устройство 102 отозвано. Текущий список отозванных: {gm.revoked}")

# 6. Проверяем старую подпись – должна быть отвергнута
valid_revoked = verifier.VerifySign(Theta, Sigma, Omega, msg, count, participants, gm.revoked)
print(f"Та же подпись после отзыва: {valid_revoked} (ожидается False)")

# 7. Новая подпись только оставшимися (101 и 103)
remaining = [d for d in devices if d.node_id != 102]
partial_sigs_new = [d.generatePartSignature(msg) for d in remaining]
Theta_n, Sigma_n, Omega_n, participants_n, count_n = Verifier.Aggregate(partial_sigs_new, I)
valid_new = verifier.VerifySign(Theta_n, Sigma_n, Omega_n, msg, count_n, participants_n, gm.revoked)
print(f"Новая подпись без отозванного: {valid_new} (ожидается True)")