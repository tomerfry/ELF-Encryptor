import sys


def main():
    if len(sys.argv) != 2:
        print('Usage: main.py <binary>')
        return 1

    binary = sys.argv[1]


if __name__ == '__main__':
    main()
