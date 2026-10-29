# Format Common Lisp source files with Emacs.
fmt:
    find . -type d -name .git -prune -o -type f \( -name '*.lisp' -o -name '*.lsp' -o -name '*.cl' -o -name '*.asd' \) -exec emacs --batch {} --eval '(progn (lisp-mode) (indent-region (point-min) (point-max)) (save-buffer))' \;
