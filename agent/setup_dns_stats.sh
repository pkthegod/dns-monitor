#!/bin/bash
# setup_dns_stats.sh — Habilita coleta de DNS Query Stats no resolver local.
#
# Detecta Unbound ou Bind9 (via systemctl) e configura o que falta para o
# dns-agent coletar RCODEs / QPS / cache hits. Idempotente: rodar 2x e seguro.
#
#   Unbound:
#     - Drop-in /etc/unbound/unbound.conf.d/zz-dns-monitor.conf habilita
#       extended-statistics + remote-control em 127.0.0.1:8953.
#     - Gera certs com unbound-control-setup se faltarem.
#     - Detecta e avisa sobre 'control-enable: no' em outros conf.d.
#
#   Bind9:
#     - Nao altera config (rndc stats funciona out of the box).
#     - Garante que o user dns-agent consegue ler /var/cache/bind/named.stats
#       (adiciona ao grupo bind se necessario).
#
# Uso:
#   bash setup_dns_stats.sh             # --check (default): mostra diff, nao escreve
#   bash setup_dns_stats.sh --apply     # aplica e reinicia o resolver
#   bash setup_dns_stats.sh --apply --force   # nao cria backups .bak
#
# Compativel com Debian 12+ e Ubuntu 22.04+. Execute como root.

set -eu
(set -o pipefail) 2>/dev/null || true

MODE="check"
FORCE=false

usage() {
    sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'
}

for arg in "$@"; do
    case "$arg" in
        --check) MODE="check" ;;
        --apply) MODE="apply" ;;
        --force) FORCE=true ;;
        -h|--help) usage; exit 0 ;;
        *) echo "ERRO: argumento desconhecido: $arg"; usage; exit 1 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "ERRO: execute como root: bash setup_dns_stats.sh [--apply]"
    exit 1
fi

echo "================================================"
echo "  DNS Monitor — Setup DNS Query Stats"
echo "  Modo: $MODE"
echo "================================================"

# ---------------------------------------------------------------------------
# Detect resolver
# ---------------------------------------------------------------------------
RESOLVER=""
if systemctl is-active --quiet unbound 2>/dev/null; then
    RESOLVER="unbound"
elif systemctl is-active --quiet bind9 2>/dev/null || systemctl is-active --quiet named 2>/dev/null; then
    RESOLVER="bind9"
else
    echo "ERRO: nenhum resolver ativo detectado (unbound / bind9 / named)."
    echo "      inicie o servico antes de rodar este script."
    exit 1
fi
echo "Resolver detectado: $RESOLVER"
echo ""

# ---------------------------------------------------------------------------
# Helpers comuns
# ---------------------------------------------------------------------------

# diff_or_create <file> <new_content>
# imprime diff colorido-ish e devolve 0 se precisa escrever, 1 se igual.
diff_or_create() {
    local file="$1"
    local new="$2"
    if [ -f "$file" ]; then
        if printf '%s' "$new" | diff -q "$file" - >/dev/null 2>&1; then
            echo "  [=] $file ja esta correto"
            return 1
        fi
        echo "  [~] $file vai ser alterado:"
        printf '%s' "$new" | diff -u "$file" - | sed 's/^/      /' || true
        return 0
    fi
    echo "  [+] $file vai ser criado:"
    printf '%s' "$new" | sed 's/^/      /'
    return 0
}

# write_atomic <file> <content>
# Escreve via tmp+mv. Cria backup .bak.YYYYMMDD-HHMMSS se arquivo existir
# e --force nao foi passado.
write_atomic() {
    local file="$1"
    local new="$2"
    local tmp="${file}.tmp.$$"
    if [ -f "$file" ] && [ "$FORCE" != true ]; then
        cp "$file" "${file}.bak.$(date +%Y%m%d-%H%M%S)"
    fi
    printf '%s' "$new" > "$tmp"
    chmod 644 "$tmp"
    mv "$tmp" "$file"
}

# ===========================================================================
# UNBOUND
# ===========================================================================
configure_unbound() {
    local DROPIN="/etc/unbound/unbound.conf.d/zz-dns-monitor.conf"
    local CONF_MAIN="/etc/unbound/unbound.conf"

    # Conteudo canonico — termina em newline.
    local CONTENT
    CONTENT='# Gerado por setup_dns_stats.sh — nao edite manualmente.
# Habilita extended-statistics + unbound-control para o dns-agent.
server:
    extended-statistics: yes
    statistics-cumulative: no
    statistics-interval: 0

remote-control:
    control-enable: yes
    control-interface: 127.0.0.1
    control-port: 8953
    server-key-file: "/etc/unbound/unbound_server.key"
    server-cert-file: "/etc/unbound/unbound_server.pem"
    control-key-file: "/etc/unbound/unbound_control.key"
    control-cert-file: "/etc/unbound/unbound_control.pem"
'

    echo "0) Validando config atual (pre-flight)..."
    local preflight
    preflight=$(unbound-checkconf 2>&1) || true
    if ! unbound-checkconf >/dev/null 2>&1; then
        echo "  [!] unbound-checkconf JA esta falhando antes de qualquer alteracao:"
        echo "$preflight" | sed 's/^/        /'
        echo ""
        echo "      Resolva o erro acima ANTES de prosseguir (geralmente um drop-in"
        echo "      em /etc/unbound/unbound.conf.d/ com typo). Modo --apply vai abortar."
        if [ "$MODE" = "apply" ]; then
            exit 1
        fi
    else
        echo "  [=] config atual valida"
    fi

    echo ""
    echo "1) Verificando conflitos de config..."
    local conflict
    conflict=$(grep -rln "control-enable:[[:space:]]*no" /etc/unbound/ 2>/dev/null || true)
    if [ -n "$conflict" ]; then
        echo "  [!] AVISO — 'control-enable: no' encontrado em:"
        echo "$conflict" | sed 's/^/        /'
        echo "      o drop-in zz-dns-monitor.conf carrega por ULTIMO (alfabetico),"
        echo "      mas se houver include explicito apos os conf.d no arquivo principal,"
        echo "      esse 'no' pode vencer. Revise manualmente se o teste no final falhar."
    fi

    # Duplicacao de control-port: unbound-checkconf nao pega isso, mas o bind() falha.
    # So contamos arquivos OUTROS alem do nosso drop-in zz-.
    local DROPIN_NAME
    DROPIN_NAME=$(basename "$DROPIN")
    local dup_port
    dup_port=$(grep -rln "control-port:" /etc/unbound/ 2>/dev/null \
                 | grep -v "/$DROPIN_NAME$" || true)
    if [ -n "$dup_port" ]; then
        echo "  [!] AVISO — 'control-port:' tambem declarado em:"
        echo "$dup_port" | sed 's/^/        /'
        echo "      duas secoes remote-control com a mesma porta = bind() falha."
        echo "      remova o(s) outro(s) ou tire o bloco remote-control: deles."
        if [ "$MODE" = "apply" ]; then
            echo "      --apply abortado para evitar quebra do unbound."
            exit 1
        fi
    fi

    if [ -z "$conflict" ] && [ -z "$dup_port" ]; then
        echo "  [=] sem conflitos detectados"
    fi

    echo ""
    echo "2) Verificando drop-in..."
    local needs_write=0
    diff_or_create "$DROPIN" "$CONTENT" || needs_write=1

    echo ""
    echo "3) Verificando certificados unbound-control..."
    local needs_setup=false
    for f in unbound_server.key unbound_server.pem unbound_control.key unbound_control.pem; do
        if [ ! -f "/etc/unbound/$f" ]; then
            needs_setup=true
            echo "  [+] /etc/unbound/$f — faltando (sera gerado)"
        fi
    done
    if ! $needs_setup; then
        echo "  [=] todos os certificados ja existem"
    fi

    echo ""
    echo "4) Verificando include do conf.d em $CONF_MAIN..."
    local needs_include=false
    if [ -f "$CONF_MAIN" ]; then
        if ! grep -qE 'include:[[:space:]]*"?/etc/unbound/unbound\.conf\.d' "$CONF_MAIN" 2>/dev/null; then
            needs_include=true
            echo "  [+] linha 'include: \"/etc/unbound/unbound.conf.d/*.conf\"' sera adicionada"
        else
            echo "  [=] include do conf.d ja presente"
        fi
    fi

    if [ "$MODE" = "check" ]; then
        echo ""
        echo "Modo --check: nada foi alterado. Rode com --apply para aplicar."
        return 0
    fi

    # ---- APPLY (transacional: snapshot + rollback se checkconf falhar) ----
    echo ""
    echo "Aplicando alteracoes..."

    # Snapshots para rollback
    local DROPIN_EXISTED=false
    [ -f "$DROPIN" ] && DROPIN_EXISTED=true
    local CONF_SNAPSHOT=""
    if [ -f "$CONF_MAIN" ]; then
        CONF_SNAPSHOT="${CONF_MAIN}.tx.$$"
        cp "$CONF_MAIN" "$CONF_SNAPSHOT"
    fi

    rollback_unbound() {
        echo "  [rollback] revertendo alteracoes..."
        if ! $DROPIN_EXISTED && [ -f "$DROPIN" ]; then
            rm -f "$DROPIN"
            echo "  [rollback] $DROPIN removido"
        elif $DROPIN_EXISTED; then
            local last_bak
            last_bak=$(ls -t "${DROPIN}.bak."* 2>/dev/null | head -1 || true)
            if [ -n "$last_bak" ]; then
                mv "$last_bak" "$DROPIN"
                echo "  [rollback] $DROPIN restaurado de $last_bak"
            fi
        fi
        if [ -n "$CONF_SNAPSHOT" ] && [ -f "$CONF_SNAPSHOT" ]; then
            mv "$CONF_SNAPSHOT" "$CONF_MAIN"
            echo "  [rollback] $CONF_MAIN restaurado"
        fi
    }

    if $needs_setup; then
        unbound-control-setup -d /etc/unbound >/dev/null
        echo "  [+] certificados gerados em /etc/unbound/"
    fi

    if [ $needs_write -eq 0 ]; then
        write_atomic "$DROPIN" "$CONTENT"
        echo "  [+] $DROPIN gravado"
    fi

    if $needs_include; then
        printf '\ninclude: "/etc/unbound/unbound.conf.d/*.conf"\n' >> "$CONF_MAIN"
        echo "  [+] include adicionado em $CONF_MAIN"
    fi

    echo ""
    echo "5) Validando config apos modificacoes..."
    local postflight
    postflight=$(unbound-checkconf 2>&1) || true
    if ! unbound-checkconf >/dev/null 2>&1; then
        echo "ERRO: unbound-checkconf falhou:"
        echo "$postflight" | sed 's/^/        /'
        rollback_unbound
        exit 1
    fi
    [ -n "$CONF_SNAPSHOT" ] && rm -f "$CONF_SNAPSHOT"
    echo "  [OK]"

    echo ""
    echo "6) Reiniciando unbound..."
    systemctl restart unbound
    sleep 2
    if ! systemctl is-active --quiet unbound; then
        echo "ERRO: unbound nao subiu. Veja: journalctl -u unbound -n 30"
        exit 1
    fi
    echo "  [OK]"

    echo ""
    echo "7) Validando coleta..."
    if unbound-control status >/dev/null 2>&1; then
        echo "  [OK] unbound-control conectou"
        local sample
        sample=$(unbound-control stats_noreset 2>/dev/null | grep -cE "^num\.(answer\.rcode|query\.type)\." || true)
        if [ "$sample" -gt 0 ]; then
            echo "  [OK] extended-statistics exporta $sample chaves de rcode/tipo"
        else
            echo "  [!] unbound respondeu mas sem rcode/tipo — extended-statistics nao surtiu efeito"
            echo "      pode haver 'extended-statistics: no' em outro conf.d. Rode:"
            echo "      grep -rn 'extended-statistics' /etc/unbound/"
            exit 1
        fi
    else
        echo "  [ERRO] unbound-control nao conectou em 127.0.0.1:8953."
        echo "         provavel causa: outro arquivo declara 'control-enable: no' depois do drop-in."
        echo "         rode: grep -rn 'control-enable' /etc/unbound/"
        exit 1
    fi
}

# ===========================================================================
# BIND9
# ===========================================================================
configure_bind9() {
    local STATS_FILE="/var/cache/bind/named.stats"
    local SERVICE_USER="dns-agent"

    echo "1) Verificando rndc..."
    if ! command -v rndc >/dev/null 2>&1; then
        echo "ERRO: rndc nao encontrado. Instale: apt-get install bind9-utils"
        exit 1
    fi
    if ! rndc status >/dev/null 2>&1; then
        echo "ERRO: 'rndc status' falhou. Verifique /etc/bind/rndc.key e que o named esta rodando."
        exit 1
    fi
    echo "  [=] rndc operacional"

    echo ""
    echo "2) Disparando rndc stats e validando dump..."
    rndc stats
    sleep 1
    if [ ! -f "$STATS_FILE" ]; then
        echo "ERRO: $STATS_FILE nao foi gerado."
        echo "      verifique 'statistics-file' em /etc/bind/named.conf.options"
        echo "      (default: \"$STATS_FILE\")"
        exit 1
    fi
    local lines
    lines=$(wc -l < "$STATS_FILE" 2>/dev/null || echo 0)
    echo "  [=] $STATS_FILE existe ($lines linhas)"

    echo ""
    echo "3) Verificando acesso do user $SERVICE_USER..."
    if ! id "$SERVICE_USER" >/dev/null 2>&1; then
        echo "  [!] user $SERVICE_USER nao existe — rode install_agent.sh primeiro"
        echo "      ou ignore se voce esta usando outro user para o agente."
        if [ "$MODE" = "check" ]; then return 0; fi
        exit 1
    fi

    # Checa 3 coisas separadamente:
    #   a) leitura do arquivo de stats (necessaria pra parse)
    #   b) leitura do rndc.key (necessaria pra disparar rndc stats)
    #   c) execucao do rndc stats end-to-end pelo dns-agent
    local need_group_fix=false
    local read_ok=false rndc_ok=false rndckey_ok=false

    if sudo -u "$SERVICE_USER" test -r "$STATS_FILE" 2>/dev/null; then
        read_ok=true
        echo "  [=] $SERVICE_USER consegue ler $STATS_FILE"
    else
        echo "  [!] $SERVICE_USER NAO consegue ler $STATS_FILE"
        need_group_fix=true
    fi

    if sudo -u "$SERVICE_USER" test -r /etc/bind/rndc.key 2>/dev/null; then
        rndckey_ok=true
        echo "  [=] $SERVICE_USER consegue ler /etc/bind/rndc.key"
    else
        echo "  [!] $SERVICE_USER NAO consegue ler /etc/bind/rndc.key (CRITICO — sem isso rndc stats falha)"
        need_group_fix=true
    fi

    if sudo -u "$SERVICE_USER" rndc stats >/dev/null 2>&1; then
        rndc_ok=true
        echo "  [=] $SERVICE_USER consegue executar 'rndc stats'"
    else
        echo "  [!] 'rndc stats' falha quando rodado como $SERVICE_USER — coleta retorna vazio"
        need_group_fix=true
    fi

    if [ "$MODE" = "check" ]; then
        echo ""
        echo "Modo --check: nada foi alterado."
        if $need_group_fix; then
            echo "Acoes pendentes:"
            echo "  usermod -aG bind $SERVICE_USER"
            echo "  systemctl restart dns_agent   # pra novo grupo entrar em vigor"
        else
            echo "Bind9 ja esta pronto para coleta — nenhuma acao necessaria."
        fi
        return 0
    fi

    # ---- APPLY ----
    if $need_group_fix; then
        echo ""
        echo "Aplicando: adicionando $SERVICE_USER ao grupo bind..."
        usermod -aG bind "$SERVICE_USER"
        echo "  [+] $SERVICE_USER agora pertence ao grupo bind"
        # Garante que rndc.key tem dono bind (caso default tenha mudado)
        if [ -f /etc/bind/rndc.key ]; then
            chgrp bind /etc/bind/rndc.key 2>/dev/null || true
            chmod 640 /etc/bind/rndc.key 2>/dev/null || true
        fi
        echo "  [!] reiniciando dns_agent pra novo grupo entrar em vigor..."
        systemctl restart dns_agent || echo "  [!] systemctl restart dns_agent falhou — reinicie manualmente"
    fi

    echo ""
    echo "Validando end-to-end..."
    sleep 1
    if sudo -u "$SERVICE_USER" rndc stats >/dev/null 2>&1; then
        echo "  [OK] $SERVICE_USER consegue rodar rndc stats"
        sleep 1
        local linecount
        linecount=$(sudo -u "$SERVICE_USER" wc -l < "$STATS_FILE" 2>/dev/null || echo 0)
        echo "  [OK] stats file tem $linecount linhas"
        echo ""
        echo "Aguarde ~10min pelo proximo ciclo de coleta. Depois valide:"
        echo "  journalctl -u dns_agent -n 30 --no-pager | grep -i stats"
    else
        echo "  [!] rndc stats ainda falha como $SERVICE_USER. Diagnostico:"
        sudo -u "$SERVICE_USER" rndc stats 2>&1 | sed 's/^/        /' || true
    fi
}

# ===========================================================================
# Main
# ===========================================================================
case "$RESOLVER" in
    unbound) configure_unbound ;;
    bind9)   configure_bind9   ;;
esac

echo ""
echo "================================================"
echo "  Concluido."
if [ "$MODE" = "check" ]; then
    echo "  Para aplicar: sudo bash $0 --apply"
fi
echo "================================================"
