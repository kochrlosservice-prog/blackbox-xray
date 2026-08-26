from circular_a import something_a  # circular back (F04)


def something_b():
    return something_a() + "b"
