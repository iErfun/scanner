inventory = {
    "Bag": 5,
    "Ball": 8,
    "Laptop": 3,
    "Mouse": 10,
    "Flash memory": 14
}

while True:
    print("\n----- Inventory Menu -----")
    print("1. Check item quantity")
    print("2. Remove some quantity of an item")
    print("3. Exit")

    choice = input("What do you want to do? (1-3): ")

    if choice == "1":
        item = input("Which item do you want to check?: ").strip()
        found = None
        for key in inventory:
            if key.lower() == item.lower():
                found = key
        if found:
            print("You have", inventory[found], found, "in your inventory.")
        else:
            print("This item is not in your inventory.")

    elif choice == "2":
        item = input("Which item do you want to remove from?: ").strip()
        found = None
        for key in inventory:
            if key.lower() == item.lower():
                found = key

        if found == None:
            print("This item is not in your inventory.")
        else:
            print("You currently have", inventory[found], found)
            amount = input("How many do you want to remove?: ")
            if amount.isdigit():
                amount = int(amount)
                if amount <= 0:
                    print("Please enter a positive number.")
                elif amount > inventory[found]:
                    print("You only have", inventory[found], "of", found)
                else:
                    inventory[found] = inventory[found] - amount
                    print(amount, found, "removed.")
                    if inventory[found] == 0:
                        del inventory[found]
                        print(found, "is now completely removed.")
                    else:
                        print("Remaining", found, ":", inventory[found])
            else:
                print("Please enter a valid number.")

    elif choice == "3":
        print("\nCurrent inventory:")
        for item in inventory:
            print(" ", item, ":", inventory[item])
        break

    else:
        print("Invalid choice. Please try again.")
