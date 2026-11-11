# Format Common Lisp source files with Emacs.
fmt:
    find . -type d -name .git -prune -o -type f \( -name '*.lisp' -o -name '*.lsp' -o -name '*.cl' -o -name '*.asd' \) -exec emacs --batch {} --eval '(progn (lisp-mode) (indent-region (point-min) (point-max)) (save-buffer))' \;

# WireGuard helpers. Run these inside `nix develop`.
# `sudo env PATH="$PATH"` keeps the dev-shell tools on sudo's PATH.

# Bring a WireGuard tunnel up.
wg-up conf:
    sudo env PATH="$PATH" "$(command -v wg-quick)" up "{{conf}}"

# Tear a WireGuard tunnel down.
wg-down conf:
    sudo env PATH="$PATH" "$(command -v wg-quick)" down "{{conf}}"

# Show the active WireGuard interfaces.
wg-show:
    sudo "$(command -v wg)" show

# Install the local challenge search dependencies.
install:
    bun install

# Run the local challenge search frontend.
search:
    bun run start

# Run the local challenge search frontend with file watching.
search-dev:
    bun run dev

# Type-check the challenge search frontend and backend.
check:
    bun run typecheck

