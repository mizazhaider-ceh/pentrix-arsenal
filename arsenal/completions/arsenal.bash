# Bash completion for PENTRIX ARSENAL
# Install: copy to /etc/bash_completion.d/arsenal or source from ~/.bashrc:
#   source /path/to/arsenal.bash

_arsenal_commands="ask autopilot checklist config dupcheck export findings goal inbox lab memory monitor notify payloads pipeline-graph plugins program recon replay report revshell scan scope serve stats templates time trends triage workflow"

_arsenal_modules() {
    # best-effort module list for --module completion
    python3 -c "import sys; sys.path.insert(0, '.'); from arsenal.modules import REGISTRY; print(' '.join(sorted(REGISTRY)))" 2>/dev/null
}

_arsenal_complete() {
    local cur prev words cword
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    local cmd=""
    local i
    for (( i=1; i<COMP_CWORD; i++ )); do
        case "${COMP_WORDS[i]}" in
            -*) ;;
            *) cmd="${COMP_WORDS[i]}"; break ;;
        esac
    done

    case "$prev" in
        --module)
            COMPREPLY=( $(compgen -W "$(_arsenal_modules)" -- "$cur") )
            return 0
            ;;
        --format)
            case "$cmd" in
                report) COMPREPLY=( $(compgen -W "html yeswehack hackerone" -- "$cur") ) ;;
                export) COMPREPLY=( $(compgen -W "nuclei burp-xml" -- "$cur") ) ;;
                trends) COMPREPLY=( $(compgen -W "html md" -- "$cur") ) ;;
            esac
            return 0
            ;;
        --shell)
            COMPREPLY=( $(compgen -W "bash zsh fish" -- "$cur") )
            return 0
            ;;
        --var|--set)
            return 0
            ;;
    esac

    if [[ -z "$cmd" ]]; then
        COMPREPLY=( $(compgen -W "$_arsenal_commands --verbose --workspace-root --help" -- "$cur") )
        return 0
    fi

    local flags="--help"
    case "$cmd" in
        recon|scan) flags="$flags --scope-file --intrusive --passive --resume --module --all" ;;
        ask) flags="$flags --plan" ;;
        triage) flags="$flags --mark-fp --fp-note" ;;
        report) flags="$flags --format --out" ;;
        trends) flags="$flags --format --out" ;;
        export) flags="$flags --format --out" ;;
        workflow) flags="$flags --target --var --out" ;;
        serve) flags="$flags --port --host" ;;
        findings) flags="$flags --status --set --to --program --payout --force" ;;
        stats|dupcheck|memory|autopilot|config|doctor|completions) flags="$flags" ;;
    esac
    case "$cmd" in
        recon|scan) flags="$flags --resume" ;;
        autopilot) flags="$flags --max-cycles --intrusive --passive" ;;
        memory) flags="$flags --add --search" ;;
        doctor) flags="$flags --json" ;;
    esac
    COMPREPLY=( $(compgen -W "$flags" -- "$cur") )
    return 0
}

complete -F _arsenal_complete arsenal
