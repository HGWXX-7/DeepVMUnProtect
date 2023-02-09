from tqdm import tqdm
from time import sleep

def sleep_with_tqdm(second):
    for i in tqdm(range(second)):
        sleep(1)
