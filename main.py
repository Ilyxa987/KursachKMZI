from GM import GroupManager
from IoT import IoT
from Verifier import Verifier

# Инициализация GM
gm = GroupManager(n=5, t=3)
gm.GenerateElepticCurve()
gm.GenerateGMKeys()
gm.GenerateGroupKeys()
G, gx, M, Mx, I = gm.GetOpens()
verifier = Verifier(G, I, gx)

# Регистрируем 6 устройств
ids = [101, 102, 103, 104, 105, 106]
devices = []
for node_id in ids:
    device = IoT(node_id)
    device.setOpens(G, gx, M, Mx, I)

    # Этап 1
    R, BI1 = gm.FirstAnonimization(node_id)
    if device.VerifyBI1(R, BI1):
        # Устройство передаёт GM свой открытый RSA-ключ
        pub_enc = device.get_public_enc_key()

        # Этап 2
        device.GenerateFirstPartKey()
        U, BI2 = device.secondAnonimization()
        gm.addMember(node_id, device.X, BI1, BI2, pub_enc)

        # GM генерирует зашифрованную часть ключа
        encrypted_y = gm.generateSecondPartKey(node_id)
        # Устройство расшифровывает и формирует полный ключ
        device.generateKey(encrypted_y)
        devices.append(device)
        print(f"Устройство {node_id} зарегистрировано (y передан зашифрованным).")

# Сообщение для подписи
msg = "Test Message"

# --- Полная подпись (все 6) ---
partial_all = [d.generatePartSignature(msg) for d in devices]
Theta, Sigma, Omega, parts, cnt = Verifier.Aggregate(partial_all, I, gm.t)
valid_all = verifier.VerifySign(Theta, Sigma, Omega, msg, cnt, parts, gm.revoked)
print(f"\nПодпись всех устройств: {valid_all} (True)")

# --- Отзыв 102 ---
gm.revokeMember(102)
print(f"\nОтозвано устройство 102. Отозванные: {gm.revoked}")
valid_old = verifier.VerifySign(Theta, Sigma, Omega, msg, cnt, parts, gm.revoked)
print(f"Старая подпись после отзыва: {valid_old} (False)")

# --- Новая подпись без 102 ---
remaining = [d for d in devices if d.node_id != 102]
partial_new = [d.generatePartSignature(msg) for d in remaining]
Theta_n, Sigma_n, Omega_n, parts_n, cnt_n = Verifier.Aggregate(partial_new, I, gm.t)
if Theta_n is not None:
    valid_new = verifier.VerifySign(Theta_n, Sigma_n, Omega_n, msg, cnt_n, parts_n, gm.revoked)
    print(f"Новая подпись (5 участников): {valid_new} (True)")

# --- Дополнительный отзыв, проверка порога ---
for rid in [103, 104, 105]:
    gm.revokeMember(rid)
print(f"\nДополнительно отозваны 103,104,105. Отозванные: {gm.revoked}")
remaining_few = [d for d in devices if d.node_id not in gm.revoked]
print(f"Оставшиеся участники: {[d.node_id for d in remaining_few]} (количество: {len(remaining_few)})")
partial_few = [d.generatePartSignature(msg) for d in remaining_few]
Theta_f, Sigma_f, Omega_f, parts_f, cnt_f = Verifier.Aggregate(partial_few, I, gm.t)
if Theta_f is None:
    print("Новая подпись НЕ создана – недостаточное количество участников (порог 3).")
else:
    print("Этого не должно произойти.")