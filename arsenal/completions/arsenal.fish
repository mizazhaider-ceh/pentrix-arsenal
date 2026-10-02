# Fish completion for PENTRIX ARSENAL
# Install: copy to ~/.config/fish/completions/arsenal.fish

set -l commands ask autopilot checklist config dupcheck export findings goal inbox lab memory monitor notify payloads pipeline-graph plugins program recon replay report revshell scan scope serve stats templates time trends triage workflow doctor completions

complete -c arsenal -f -n '__fish_use_subcommand' -a "$commands"

# global flags
complete -c arsenal -f -n '__fish_use_subcommand' -s v -l verbose -d 'Verbose logging'
complete -c arsenal -f -n '__fish_use_subcommand' -l workspace-root -d 'Workspace root directory' -r -a "(__fish_complete_directories)"

# module names for --module
function __arsenal_modules
    python3 -c "import sys; sys.path.insert(0, '.'); from arsenal.modules import REGISTRY; print('\n'.join(sorted(REGISTRY)))" 2>/dev/null
end

for cmd in recon scan
    complete -c arsenal -f -n "__fish_seen_subcommand_from $cmd" -l module -d 'Run a single module' -r -a "(__arsenal_modules)"
    complete -c arsenal -f -n "__fish_seen_subcommand_from $cmd" -l all -d 'Run every applicable module'
    complete -c arsenal -f -n "__fish_seen_subcommand_from $cmd" -l scope-file -d 'Scope file' -r
    complete -c arsenal -f -n "__fish_seen_subcommand_from $cmd" -l intrusive -d 'Allow intrusive modules'
    complete -c arsenal -f -n "__fish_seen_subcommand_from $cmd" -l passive -d 'Passive-only mode'
    complete -c arsenal -f -n "__fish_seen_subcommand_from $cmd" -l resume -d 'Resume a previous run'
end

complete -c arsenal -f -n '__fish_seen_subcommand_from ask' -l plan -d 'Plan a hunt from natural language' -r
complete -c arsenal -f -n '__fish_seen_subcommand_from triage' -l mark-fp -d 'Record a false positive' -r
complete -c arsenal -f -n '__fish_seen_subcommand_from triage' -l fp-note -d 'FP analyst note' -r
complete -c arsenal -f -n '__fish_seen_subcommand_from report' -l format -d 'Report format' -r -a "html yeswehack hackerone"
complete -c arsenal -f -n '__fish_seen_subcommand_from report' -l out -d 'Output path' -r
complete -c arsenal -f -n '__fish_seen_subcommand_from trends' -l format -d 'Trend format' -r -a "html md"
complete -c arsenal -f -n '__fish_seen_subcommand_from trends' -l out -d 'Output path' -r
complete -c arsenal -f -n '__fish_seen_subcommand_from export' -l format -d 'Export format' -r -a "nuclei burp-xml"
complete -c arsenal -f -n '__fish_seen_subcommand_from export' -l out -d 'Output path' -r
complete -c arsenal -f -n '__fish_seen_subcommand_from workflow' -l target -d 'Target override' -r
complete -c arsenal -f -n '__fish_seen_subcommand_from workflow' -l var -d 'Variable override k=v' -r
complete -c arsenal -f -n '__fish_seen_subcommand_from workflow' -l out -d 'Output path' -r
complete -c arsenal -f -n '__fish_seen_subcommand_from serve' -l port -d 'Port' -r
complete -c arsenal -f -n '__fish_seen_subcommand_from serve' -l host -d 'Interface' -r
complete -c arsenal -f -n '__fish_seen_subcommand_from findings' -l status -d 'Filter by status' -r
complete -c arsenal -f -n '__fish_seen_subcommand_from findings' -l set -d 'Finding id' -r
complete -c arsenal -f -n '__fish_seen_subcommand_from findings' -l to -d 'New status' -r
complete -c arsenal -f -n '__fish_seen_subcommand_from findings' -l program -d 'Program' -r
complete -c arsenal -f -n '__fish_seen_subcommand_from findings' -l payout -d 'Amount' -r
complete -c arsenal -f -n '__fish_seen_subcommand_from findings' -l force -d 'Override status flow'
complete -c arsenal -f -n '__fish_seen_subcommand_from completions' -l shell -d 'Shell' -r -a "bash zsh fish"
complete -c arsenal -f -n '__fish_seen_subcommand_from doctor' -l json -d 'Machine-readable output'
complete -c arsenal -f -n '__fish_seen_subcommand_from autopilot' -l max-cycles -d 'Max cycles' -r
complete -c arsenal -f -n '__fish_seen_subcommand_from autopilot' -l intrusive -d 'Allow intrusive modules'
complete -c arsenal -f -n '__fish_seen_subcommand_from autopilot' -l passive -d 'Passive-only mode'
complete -c arsenal -f -n '__fish_seen_subcommand_from memory' -l add -d 'Add note' -r
complete -c arsenal -f -n '__fish_seen_subcommand_from memory' -l search -d 'Search' -r
