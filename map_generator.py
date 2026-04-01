import os

ignore_dirs = {'.git', 'node_modules', '.vite', 'dist', 'build', 'out', 'coverage', '.cache', 'logs', 'assets', 'public'}

def generate_map():
    with open('code_map.md', 'w', encoding='utf-8') as f:
        f.write('# Sentinel Code Map\n```text\n')
        f.write('sentinel/\n')
        def print_tree(d, indent=''):
            try:
                entries = sorted(os.listdir(d))
            except PermissionError:
                return
            for i, e in enumerate(entries):
                p = os.path.join(d, e)
                is_last = (i == len(entries) - 1)
                prefix = '└── ' if is_last else '├── '
                child_indent = '    ' if is_last else '│   '
                
                if os.path.isdir(p):
                    if e not in ignore_dirs:
                        f.write(f'{indent}{prefix}{e}/\n')
                        print_tree(p, indent + child_indent)
                else:
                    f.write(f'{indent}{prefix}{e}\n')
        
        print_tree('src')
        f.write('```\n')

if __name__ == '__main__':
    generate_map()
