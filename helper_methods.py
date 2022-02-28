import time

from PIL import ImageGrab


def list_to_path(lis: list):
    return ''.join(lis[i] + ' ' if len(lis) > 1 else lis[i] for i in range(len(lis)))


def screenshot() -> str:
    snapshot = ImageGrab.grab()
    save_path = time.asctime()[4:8] + time.asctime()[8:10] + "-" + time.asctime()[20:] + "-" + time.asctime()[
                                                                                               11:19].replace(
        ':', '_') + ".jpg"  # This line slices from the module time only the date and time,
    # and replaces every ':' with '-' so the file will be able to be saved.
    snapshot.save(save_path)
    return save_path
