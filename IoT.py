from tinyec import registry
import tinyec


class IoT:
    ID: int
    x: int
    X: tinyec.ec.Point
    u: int
    U: tinyec.ec.Point
    BI: int
    s: int
    S: tinyec.ec.Point
    y: int
    O: tinyec.ec.Point
    m: str
    lu: str

    def __init__(self):
        print('IoT init')