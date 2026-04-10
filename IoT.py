from tinyec import registry
import tinyec


class IoT:
    ID: int  # Идентификатор IoT
    x: int  # Случайный закрытый ключ
    X: tinyec.ec.Point  # Открытый ключ
    u: int  # Случайное число
    U: tinyec.ec.Point  #
    BI: int
    s: int
    S: tinyec.ec.Point
    y: int  # Случайное число
    O: tinyec.ec.Point
    m: str  # Сообщение
    lu: str  # Хэш сообщения

    def __init__(self):
        print('IoT init')