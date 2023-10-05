

def tonelli_shanks(n, p):
    assert pow(n, (p - 1) // 2, p) == 1

    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1

    if s == 1:
        return pow(n, (p + 1) // 4, p)

    for z in range(2, p):
        if pow(z, (p - 1) // 2, p) == p - 1:
            break

    c = pow(z, q, p)
    r = pow(n, (q + 1) // 2, p)
    t = pow(n, q, p)
    m = s

    while (t - 1) % p != 0:
        t2 = t
        i = 0
        for i in range(1, m):
            t2 = pow(t2, 2, p)
            if (t2 - 1) % p == 0:
                break

        b = pow(c, 1 << (m - i - 1), p)
        r = (r * b) % p
        c = (b * b) % p
        t = (t * c) % p
        m = i

    return r


def secp256k1_y_from_x_eth(x, yparity):
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    y_squared = (pow(x, 3, p) + 7) % p
    y1 = tonelli_shanks(y_squared, p)

    if y1%2 == yparity:
        return y1
    else:
        return (-y1) % p


def main():
	x = 0x117f692257b2331233b5705ce9c682be8719ff1b2b64cbca290bd6faeb54423e

	y1, y2 = secp256k1_y_from_x(x)
	print(hex(y1), hex(y2))  #this is just giving y and p-y ofc


if __name__ == "__main__":
	main()

