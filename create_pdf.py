import os

new_file = open(r'MyCode.txt', 'w')
for file in os.listdir('bin'):
    print(file)
    if file.endswith('.py'):
        new_file.write(f'File Name: {file} \n##################################################################\n')
        new_file.write(open(os.getcwd()+'/bin/'+file, 'r').read())

for file in os.listdir('templates'):
    print(file)
    if file.endswith('.html'):
        new_file.write(f'File Name: {file} \n##################################################################\n')
        new_file.write(open(os.getcwd()+'/templates/'+file, 'r').read())

for file in os.listdir('API'):
    print(file)
    if file.endswith('.py'):
        new_file.write(f'File Name: {file} \n##################################################################\n')
        new_file.write(open(os.getcwd()+'/API/'+file, 'r').read())
