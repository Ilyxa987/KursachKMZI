from GM import GroupManager
from IoT import IoT
from Verifier import Verifier

# 1. Инициализация GM
gm = GroupManager(n=5, t=3)
gm.GenerateElepticCurve()
gm.GenerateGMKeys()
gm.GenerateGroupKeys()
G, gx, M, Mx, I = gm.GetOpens()

# 2. Регистрируем устройства
ids = [101, 102, 103, 104, 105, 106]
devices = []
for node_id in ids:
    dev = IoT(node_id)
    dev.setOpens(G, gx, M, Mx, I)
    pub_enc = dev.get_public_enc_key()
    R, BI1 = gm.FirstAnonimization(node_id)
    if dev.VerifyBI1(R, BI1):
        dev.GenerateFirstPartKey()
        U, BI2 = dev.secondAnonimization()
        gm.addMember(node_id, dev.X, BI1, BI2, pub_enc)
        enc_y = gm.generateSecondPartKey(node_id)
        dev.generateKey(enc_y)
        devices.append(dev)
        print(f"Устройство {node_id} зарегистрировано.")

# 3. Сообщаем каждому устройству полный список активных ID (все зарегистрированные)
active_ids = [d.node_id for d in devices]
for dev in devices:
    dev.set_active_nodes(active_ids)

msg = "Test Message"

# 4. Выбор общего лидера (все устройства вычисляют одинаково)
leader_id = devices[0].elect_leader()  # используем любое устройство, результат одинаков
print(f"\nВыбран лидер: устройство {leader_id}")

# Найдём объект лидера
leader = next(d for d in devices if d.node_id == leader_id)

# 5. Все устройства генерируют частичные подписи
partial_sigs_dict = {}
for dev in devices:
    ps = dev.generatePartSignature(msg)
    partial_sigs_dict[dev.node_id] = ps

# 6. Лидер собирает подписи (в реальности получает по сети) и агрегирует
group_sig = leader.aggregate_signatures(partial_sigs_dict, gm.t)
if group_sig[0] is None:
    print("Не удалось агрегировать подпись (недостаточно участников).")
    exit()

Theta, Sigma, Omega, participants, count = group_sig
print("Агрегированная групповая подпись сформирована.")

# 7. Лидер рассылает подпись (broadcast)
leader.broadcast_signature(group_sig)

# 8. Каждое устройство проверяет полученную подпись
print("\nПроверка подписи всеми устройствами:")
for dev in devices:
    valid = dev.verify_group_signature(group_sig, msg, gm.revoked)
    print(f"Устройство {dev.node_id}: {valid}")

# 9. Отзыв устройства 102
print("\n--- Отзыв устройства 102 ---")
gm.revokeMember(102)

# Проверка старой подписи теперь недействительна для всех
print("Проверка старой подписи после отзыва:")
for dev in devices:
    valid = dev.verify_group_signature(group_sig, msg, gm.revoked)
    print(f"Устройство {dev.node_id}: {valid}")

# 10. Формирование новой подписи без отозванного участника
active_after = [d for d in devices if d.node_id not in gm.revoked]
if len(active_after) >= gm.t:
    # Обновляем списки активных узлов
    new_active_ids = [d.node_id for d in active_after]
    for d in active_after:
        d.set_active_nodes(new_active_ids)

    # Новый лидер
    new_leader_id = active_after[0].elect_leader()
    new_leader = next(d for d in active_after if d.node_id == new_leader_id)
    print(f"\nНовый лидер: устройство {new_leader_id}")

    # Сбор частичных подписей
    new_partial = {}
    for d in active_after:
        new_partial[d.node_id] = d.generatePartSignature(msg)

    new_group_sig = new_leader.aggregate_signatures(new_partial, gm.t)
    if new_group_sig[0] is not None:
        new_leader.broadcast_signature(new_group_sig)
        print("\nПроверка новой подписи оставшимися устройствами:")
        for d in active_after:
            valid = d.verify_group_signature(new_group_sig, msg, gm.revoked)
            print(f"Устройство {d.node_id}: {valid}")
    else:
        print("Не удалось создать новую подпись (порог не пройден).")
else:
    print("Недостаточно активных устройств для создания новой подписи.")