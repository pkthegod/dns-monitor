/**
 * trace-map.js — Renderiza saltos do dig_trace em mapa 2D Leaflet.
 *
 * API publica:
 *   TraceMap.render2D(container, hops, geoMap, options) -> Leaflet map instance | null
 *
 * Lazy init: a aba "Mapa 2D" so chama isso na primeira vez que e ativada.
 * Reuso: chamar de novo no mesmo container destroi instancia anterior antes.
 *
 * Tiles: CartoDB Dark Matter / Light Voyager (escolhe pelo data-theme do html).
 * Animacao: hops aparecem em sequencia (250ms cada) com polyline crescendo.
 * AntPath: efeito "fluxo" continuo apos render completo.
 *
 * Dependencias globais (carregadas via CDN no admin.html):
 *   - L (Leaflet 1.9+)
 *   - L.Polyline.antPath (plugin leaflet-ant-path)
 */

(function (global) {
  'use strict';

  if (typeof L === 'undefined') {
    console.error('TraceMap: Leaflet nao carregado — verifique <script> no admin.html');
    return;
  }

  // Tile providers (escolhidos pra combinar com tema)
  // CartoDB usa subdomains a-d e suporta retina (@2x via {r}).
  const TILES = {
    dark: {
      url: 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OSM</a> &copy; <a href="https://carto.com/attributions">CARTO</a>',
      subdomains: 'abcd',
      maxZoom: 19,
    },
    light: {
      url: 'https://{s}.basemaps.cartocdn.com/voyager/{z}/{x}/{y}{r}.png',
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OSM</a> &copy; <a href="https://carto.com/attributions">CARTO</a>',
      subdomains: 'abcd',
      maxZoom: 19,
    },
  };

  function pickTileConfig() {
    const theme = (document.documentElement.getAttribute('data-theme') || 'dark').toLowerCase();
    return TILES[theme] || TILES.dark;
  }

  // Cores devem casar com lat-fast/mid/slow/dead do admin.css
  function colorByLatency(ms) {
    if (ms == null) return '#7aa2f7'; // blue
    if (ms < 50)    return '#9ece6a'; // green
    if (ms < 200)   return '#7aa2f7'; // blue
    if (ms < 500)   return '#e0af68'; // yellow
    return '#f7768e';                  // red
  }

  function escHtml(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function hopTypeLabel(idx, total) {
    if (idx === 0) return 'ROOT';
    if (idx === total - 1) return 'ANSWER';
    return 'AUTH';
  }

  function makeHopMarker(hop, geo, idx, total) {
    const color = colorByLatency(hop.latency_ms);
    const labelType = hopTypeLabel(idx, total);

    // divIcon = HTML custom como marker — permite numero do hop dentro do circulo
    const icon = L.divIcon({
      className: 'trace-marker',
      html: '<div class="trace-marker-bubble" style="background:' + color + ';border-color:' + color + '">' + (idx + 1) + '</div>',
      iconSize: [28, 28],
      iconAnchor: [14, 14],
    });

    const marker = L.marker([geo.lat, geo.lon], { icon, opacity: 0, riseOnHover: true });

    const cityCountry = [geo.city, geo.countryCode].filter(Boolean).join(', ');
    const ispOrg = geo.isp || geo.org || '';
    const popupHtml =
      '<div class="trace-popup">' +
        '<div class="trace-popup-title" style="color:' + color + '">Hop ' + (idx + 1) + ' &middot; ' + labelType + '</div>' +
        '<div class="trace-popup-ip">' + escHtml(hop.server_ip) + '</div>' +
        (hop.server_name && hop.server_name !== hop.server_ip
          ? '<div class="trace-popup-name">' + escHtml(hop.server_name) + '</div>' : '') +
        (hop.zone ? '<div class="trace-popup-zone"><span>zona</span> ' + escHtml(hop.zone) + '</div>' : '') +
        (cityCountry ? '<div class="trace-popup-geo">' + escHtml(cityCountry) + '</div>' : '') +
        (ispOrg ? '<div class="trace-popup-isp">' + escHtml(ispOrg) + '</div>' : '') +
        (hop.latency_ms != null
          ? '<div class="trace-popup-lat" style="color:' + color + '">' + hop.latency_ms + 'ms</div>' : '') +
      '</div>';
    marker.bindPopup(popupHtml, { maxWidth: 280, closeButton: true });
    return marker;
  }

  function hopsWithValidGeo(hops, geoMap) {
    return hops
      .map((hop, idx) => ({ hop, idx, geo: geoMap[hop.server_ip] || null }))
      .filter(it => {
        const g = it.geo;
        return g && g.status === 'success'
          && typeof g.lat === 'number' && typeof g.lon === 'number';
      });
  }

  function emptyState(container) {
    container.innerHTML =
      '<div class="trace-map-empty">' +
        '<div class="trace-map-empty-title">Sem geolocalização disponível</div>' +
        '<div class="trace-map-empty-hint">' +
          'ip-api.com retornou erro ou os IPs dos saltos sao privados/anycast sem rota geo. ' +
          'Tente outro dominio ou outro resolver.' +
        '</div>' +
      '</div>';
  }

  /**
   * Renderiza o mapa 2D com revelacao sequencial dos saltos.
   * @param {HTMLElement} container — div onde o mapa sera renderizado
   * @param {Array} hops — data.trace do payload do dig_trace
   * @param {Object} geoMap — { ip: { lat, lon, city, countryCode, isp, ... } }
   * @param {Object} [options] — { animateMs: 250, antPathDelay: 600 }
   * @returns {L.Map | null}
   */
  function render2D(container, hops, geoMap, options) {
    options = options || {};
    const animateMs = options.animateMs != null ? options.animateMs : 250;
    const antDelay = options.antPathDelay != null ? options.antPathDelay : 600;

    // Cleanup de instancia anterior pra suportar re-render no mesmo container
    if (container._traceMap) {
      try { container._traceMap.remove(); } catch (_) {}
      container._traceMap = null;
    }
    container.innerHTML = '';

    const items = hopsWithValidGeo(hops || [], geoMap || {});
    if (items.length === 0) {
      emptyState(container);
      return null;
    }

    // Container precisa de altura definida pra Leaflet calcular size
    if (!container.style.height) {
      container.style.height = '480px';
    }

    const map = L.map(container, {
      worldCopyJump: true,
      preferCanvas: true,
      zoomControl: true,
      attributionControl: true,
    });
    container._traceMap = map;

    const tileCfg = pickTileConfig();
    L.tileLayer(tileCfg.url, tileCfg).addTo(map);

    // Fit bounds com padding generoso pra marcadores nao colarem na borda
    const latlngs = items.map(it => [it.geo.lat, it.geo.lon]);
    const bounds = L.latLngBounds(latlngs);
    if (items.length === 1) {
      // Bounds de 1 ponto vira degenerado — usa setView com zoom fixo
      map.setView(latlngs[0], 5);
    } else {
      map.fitBounds(bounds, { padding: [40, 40], maxZoom: 6 });
    }

    // Renderiza cada hop em sequencia + cresce a polyline
    let pathLayer = null;
    let timeoutHandles = [];

    items.forEach((it, i) => {
      const handle = setTimeout(() => {
        const marker = makeHopMarker(it.hop, it.geo, it.idx, hops.length);
        marker.addTo(map);
        // Fade-in suave
        marker.setOpacity(0);
        setTimeout(() => marker.setOpacity(1), 50);

        // Polyline crescendo: cada hop adiciona ao trajeto cumulativo
        if (i > 0) {
          if (pathLayer) {
            try { map.removeLayer(pathLayer); } catch (_) {}
          }
          const partial = latlngs.slice(0, i + 1);
          // AntPath cria polyline animada (efeito de fluxo). Se plugin nao
          // carregou, cai pra polyline normal.
          if (L.polyline.antPath) {
            pathLayer = L.polyline.antPath(partial, {
              delay: antDelay,
              dashArray: [10, 20],
              weight: 2,
              color: 'rgba(122, 162, 247, 0.75)',
              pulseColor: 'rgba(255, 255, 255, 0.85)',
              paused: false,
              reverse: false,
              hardwareAccelerated: true,
            }).addTo(map);
          } else {
            pathLayer = L.polyline(partial, {
              color: '#7aa2f7', weight: 2, opacity: 0.7,
            }).addTo(map);
          }
        }
      }, i * animateMs);
      timeoutHandles.push(handle);
    });

    // Expor handles pra abort se modal fechar antes da animacao terminar
    map._traceTimeoutHandles = timeoutHandles;

    return map;
  }

  // ===========================================================================
  // 3D — Globe.gl (Three.js bundled). Auto-rotate + arcos animados estilo
  // "DDoS attack map". Texturas carregadas do three-globe via jsdelivr.
  // ===========================================================================

  // URLs das texturas — mantidas em jsdelivr (CSP img-src ja libera).
  // Self-host eventual: copiar pra backend/static/img/ e ajustar paths.
  const GLOBE_TEXTURES = {
    dark:  'https://cdn.jsdelivr.net/npm/three-globe@2.31.1/example/img/earth-night.jpg',
    light: 'https://cdn.jsdelivr.net/npm/three-globe@2.31.1/example/img/earth-blue-marble.jpg',
    bump:  'https://cdn.jsdelivr.net/npm/three-globe@2.31.1/example/img/earth-topology.png',
  };

  function pickGlobeImage() {
    const theme = (document.documentElement.getAttribute('data-theme') || 'dark').toLowerCase();
    return theme === 'light' ? GLOBE_TEXTURES.light : GLOBE_TEXTURES.dark;
  }

  function buildArcs(items) {
    const arcs = [];
    for (let i = 0; i < items.length - 1; i++) {
      const a = items[i], b = items[i + 1];
      // Cor do arco = cor do hop de DESTINO (gradiente subtil do source pro dest)
      const color = colorByLatency(b.hop.latency_ms);
      arcs.push({
        startLat: a.geo.lat,
        startLng: a.geo.lon,
        endLat: b.geo.lat,
        endLng: b.geo.lon,
        // Globe.gl aceita array [start, end] pra gradiente; replicar mesma cor
        color: [color, color],
      });
    }
    return arcs;
  }

  function buildPoints(items, totalHops) {
    return items.map(it => ({
      lat: it.geo.lat,
      lng: it.geo.lon,
      color: colorByLatency(it.hop.latency_ms),
      hop: it.hop,
      geo: it.geo,
      idx: it.idx,
      labelType: hopTypeLabel(it.idx, totalHops),
    }));
  }

  /**
   * Renderiza globo 3D com saltos como pontos + arcos animados entre eles.
   * Auto-rotate ate o usuario interagir (mouse drag/zoom para o spin).
   *
   * @param {HTMLElement} container — div onde o globo sera renderizado
   * @param {Array} hops — data.trace
   * @param {Object} geoMap — { ip: { lat, lon, ... } }
   * @param {Object} [options] — { autoRotate, arcAnimateMs }
   * @returns {Object | null} — instancia Globe.gl ou null se sem geo
   */
  function render3D(container, hops, geoMap, options) {
    options = options || {};
    const autoRotate = options.autoRotate !== false;  // default true
    const arcAnimMs = options.arcAnimateMs || 2000;

    // Cleanup de instancia anterior (3D ou 2D)
    destroy(container);

    if (typeof Globe === 'undefined') {
      container.innerHTML = '<div class="trace-map-empty"><div class="trace-map-empty-title">Globe.gl nao carregou</div><div class="trace-map-empty-hint">Verifique conexao com cdn.jsdelivr.net + bloco de imports no admin.html</div></div>';
      return null;
    }

    const items = hopsWithValidGeo(hops || [], geoMap || {});
    if (items.length === 0) {
      emptyState(container);
      return null;
    }

    if (!container.style.height) {
      container.style.height = '480px';
    }
    // Globe.gl mede container.offsetWidth/Height pra setar canvas size.
    // Bug visto em prod (2026-05-03): se panel acabou de virar display:'',
    // o browser ainda nao fez reflow no momento do init -> offsetWidth fica
    // 0 ou stale -> canvas WebGL vaza pra fora do container e overflow:hidden
    // clipa metade do globo. Fix: medir EXPLICITAMENTE clientWidth/Height e
    // passar via API .width()/.height(). Caller deve usar requestAnimationFrame
    // pra garantir que esse codigo so roda apos reflow.
    const w0 = container.clientWidth || 600;
    const h0 = container.clientHeight || 480;

    const points = buildPoints(items, hops.length);
    const arcs = buildArcs(items);

    const world = Globe()
      (container)
      .width(w0)
      .height(h0)
      .globeImageUrl(pickGlobeImage())
      .bumpImageUrl(GLOBE_TEXTURES.bump)
      .backgroundColor('rgba(0,0,0,0)')
      .atmosphereColor('#7aa2f7')
      .atmosphereAltitude(0.18)
      // Pontos (hops)
      .pointsData(points)
      .pointLat('lat')
      .pointLng('lng')
      .pointColor('color')
      .pointAltitude(0.012)
      .pointRadius(0.55)
      .pointLabel(p => {
        const cityCountry = [p.geo.city, p.geo.countryCode].filter(Boolean).join(', ');
        const ispOrg = p.geo.isp || p.geo.org || '';
        return (
          '<div class="globe-tooltip">' +
            '<div class="globe-tooltip-title" style="color:' + p.color + '">Hop ' + (p.idx + 1) + ' &middot; ' + p.labelType + '</div>' +
            '<div class="globe-tooltip-ip">' + escHtml(p.hop.server_ip) + '</div>' +
            (cityCountry ? '<div class="globe-tooltip-geo">' + escHtml(cityCountry) + '</div>' : '') +
            (ispOrg ? '<div class="globe-tooltip-isp">' + escHtml(ispOrg) + '</div>' : '') +
            (p.hop.latency_ms != null
              ? '<div class="globe-tooltip-lat" style="color:' + p.color + '">' + p.hop.latency_ms + 'ms</div>' : '') +
          '</div>'
        );
      })
      // Arcos (conexoes entre hops sucessivos)
      .arcsData(arcs)
      .arcColor('color')
      .arcAltitude(0.28)
      .arcStroke(0.45)
      .arcDashLength(0.4)
      .arcDashGap(2)
      .arcDashAnimateTime(arcAnimMs);

    // Centraliza no centroide dos hops com altitude que mostra o globo todo
    const avgLat = items.reduce((s, it) => s + it.geo.lat, 0) / items.length;
    const avgLng = items.reduce((s, it) => s + it.geo.lon, 0) / items.length;
    world.pointOfView({ lat: avgLat, lng: avgLng, altitude: 2.4 }, 1500);

    // Auto-rotate suave ate user interagir
    const controls = world.controls();
    if (controls) {
      controls.autoRotate = autoRotate;
      controls.autoRotateSpeed = 0.4;
      controls.enableDamping = true;
      controls.dampingFactor = 0.1;
      // Para o auto-rotate ao primeiro arrastar/zoom — UX padrao mapas 3D
      const stopRotate = () => { controls.autoRotate = false; };
      controls.addEventListener('start', stopRotate, { once: true });
    }

    // ResizeObserver: ajusta canvas se modal/viewport redimensiona.
    // Sem isso, redimensionar a janela com mapa aberto deixa globo deslocado.
    let ro = null;
    if (typeof ResizeObserver !== 'undefined') {
      ro = new ResizeObserver(entries => {
        for (const entry of entries) {
          const cr = entry.contentRect;
          if (cr.width > 0 && cr.height > 0) {
            world.width(cr.width).height(cr.height);
          }
        }
      });
      ro.observe(container);
    }
    world._resizeObserver = ro;

    container._traceGlobe = world;
    return world;
  }

  /**
   * Limpa timeouts pendentes + destroi mapa (2D ou 3D). Chamar quando
   * modal fechar pra evitar leak de listeners + WebGL context.
   */
  function destroy(container) {
    if (!container) return;
    // 2D (Leaflet)
    if (container._traceMap) {
      const m = container._traceMap;
      if (m._traceTimeoutHandles) {
        m._traceTimeoutHandles.forEach(clearTimeout);
      }
      try { m.remove(); } catch (_) {}
      container._traceMap = null;
    }
    // 3D (Globe.gl) — sem .destroy() oficial; limpar DOM mata o canvas WebGL,
    // controls() handlers ficam orfaos mas sem ref (GC pega).
    if (container._traceGlobe) {
      const w = container._traceGlobe;
      try {
        if (w._resizeObserver) {
          w._resizeObserver.disconnect();
          w._resizeObserver = null;
        }
        if (w.controls && typeof w.controls === 'function') {
          const c = w.controls();
          if (c && c.dispose) c.dispose();
        }
      } catch (_) {}
      container._traceGlobe = null;
    }
    container.innerHTML = '';
  }

  global.TraceMap = { render2D, render3D, destroy };
})(window);
