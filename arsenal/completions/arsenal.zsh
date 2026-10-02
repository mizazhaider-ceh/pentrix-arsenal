#compdef arsenal
# Zsh completion for PENTRIX ARSENAL
# Install: copy to a directory in your $fpath, e.g. ~/.zsh/completions/_arsenal

_arsenal() {
    local -a commands
    commands=(
        'ask:Ask Arsenal about a target, or plan a hunt'
        'autopilot:Run the agentic recon loop against a target'
        'checklist:Manage methodology checklists'
        'config:Show or update configuration'
        'dupcheck:Dedup findings and warn about likely duplicates'
        'export:Export findings/URLs to tool formats'
        'findings:List and manage bounty findings (CRM)'
        'goal:Track hunting goals'
        'inbox:OOB callback inbox'
        'lab:Intentionally-vulnerable lab fixtures'
        'memory:Inspect or annotate the hunt memory'
        'monitor:Continuous monitoring'
        'notify:Notification helpers'
        'payloads:Payload management'
        'pipeline-graph:Visualize the recon pipeline'
        'plugins:List loaded user plugins'
        'program:Track bounty programs'
        'recon:Run the event-driven recon pipeline'
        'replay:Replay a logged session'
        'report:Generate assessment reports'
        'revshell:Reverse shell helpers'
        'scan:Run one or all scan modules'
        'scope:Manage scan scope'
        'serve:Serve the read-only web dashboard and REST API'
        'stats:Bounty totals across all targets'
        'templates:Report template library'
        'time:Time tracking'
        'trends:Trend graphs across hunts'
        'triage:AI-triage the stored findings for a target'
        'workflow:Run declarative YAML module workflows'
        'doctor:Self-check environment, config and credentials'
        'completions:Print shell completion scripts'
    )

    _arguments -C \
        '--verbose[Verbose logging]' \
        '--workspace-root[Workspace root directory]:dir:_files -/' \
        '1: :->command' \
        '*:: :->args' && return

    case $state in
        command)
            _describe -t commands 'arsenal command' commands
            ;;
        args)
            local cmd="${words[1]}"
            case "$cmd" in
                recon|scan)
                    _arguments \
                        '--module[Run a single module]:module:_arsenal_modules' \
                        '--all[Run every applicable module]' \
                        '--scope-file[Scope file]:file:_files' \
                        '--intrusive[Allow intrusive modules]' \
                        '--passive[Passive-only mode]' \
                        '--resume[Resume a previous run]' \
                        '1:target:'
                    ;;
                ask)
                    _arguments '--plan[Plan a hunt from natural language]:request:' '1:target:'
                    ;;
                triage)
                    _arguments '--mark-fp[Record a false positive]:finding id:' '--fp-note[FP note]:note:' '1:target:'
                    ;;
                report)
                    _arguments '--format[Report format]:(html yeswehack hackerone)' '--out[Output path]:file:_files' '1:target:'
                    ;;
                trends|export)
                    _arguments '--format[Format]:(html md nuclei burp-xml)' '--out[Output path]:file:_files' '1:target:'
                    ;;
                workflow)
                    _arguments '--target[Target override]:' '--var[Variable override k=v]:' '--out[Output path]:file:_files'
                    ;;
                serve)
                    _arguments '--port[Port]:' '--host[Interface]:'
                    ;;
                findings)
                    _arguments '--status[Filter by status]:' '--set[Finding id]:' '--to[New status]:' '--program[Program]:' '--payout[Amount]:' '--force[Override status flow]' '1:target:'
                    ;;
                completions)
                    _arguments '--shell[Shell]:(bash zsh fish)'
                    ;;
                doctor)
                    _arguments '--json[Machine-readable output]'
                    ;;
                *)
                    _arguments '1:target:'
                    ;;
            esac
            ;;
    esac
}

_arsenal_modules() {
    local -a mods
    mods=(${(f)"$(python3 -c "import sys; sys.path.insert(0, '.'); from arsenal.modules import REGISTRY; print('\n'.join(sorted(REGISTRY)))" 2>/dev/null)"})
    _describe -t modules 'module' mods
}

_arsenal "$@"
