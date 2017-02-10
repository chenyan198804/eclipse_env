
while True:
    i = int(input("please input a number"))
    if i > 5:
        print("i > 5")
        if i < 9:
            print("i < 9")
        else:
            print("i > 9")
            break
    else:
        print("i < 5")
        break

print("game over",i)
    