import os

try:

    mpw_dir = os.getcwd() + '\\passwords\\master-password\\master-password.pckl'
    os.remove(mpw_dir)

except:

    pass

current_dir = os.getcwd() + '\\passwords'
for f in os.listdir(current_dir):
    if not f.endswith(".pckl"):
        continue
    os.remove(os.path.join(current_dir, f))