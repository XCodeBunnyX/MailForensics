// ============================================================
// MailForensics — Relationship Graph (D3.js)
// ============================================================

class ThreatGraph {
  constructor(containerId, result) {
    this.containerId = containerId;
    this.result = result;
    this.width = 0;
    this.height = 400;
  }

  build() {
    const container = document.getElementById(this.containerId);
    if (!container) return;
    container.innerHTML = '';
    this.width = container.offsetWidth || 700;

    const nodes = [];
    const links = [];

    // Central email node
    nodes.push({ id: 'email', label: 'Email', type: 'email', size: 28, x: this.width / 2, y: this.height / 2 });

    // Sender
    const rawFrom = this.result.email?.from || this.result.sender?.from || 'Unknown Sender';
    const senderFrom = rawFrom.replace(/.*<(.+)>/, '$1').trim();
    nodes.push({ id: 'sender', label: senderFrom.length > 30 ? senderFrom.slice(0, 27) + '...' : senderFrom, type: 'sender', size: 20 });
    links.push({ source: 'sender', target: 'email', label: 'From', risk: 'critical' });

    // Reply-To
    const replyTo = this.result.email?.replyTo || this.result.sender?.replyTo;
    if (replyTo && replyTo !== 'N/A' && replyTo !== 'Not available') {
      nodes.push({ id: 'replyto', label: replyTo.length > 30 ? replyTo.slice(0, 27) + '...' : replyTo, type: 'replyto', size: 16 });
      links.push({ source: 'email', target: 'replyto', label: 'Reply-To', risk: 'high' });
    }

    // Observable Infrastructure IPs
    const ips = (this.result.candidateRelays?.map(c => c.ip) || this.result.geolocation?.map(g => g.ip) || this.result.ips || [])
      .filter(Boolean)
      .slice(0, 4);

    ips.forEach((ip) => {
      const geo = (this.result.geolocation || this.result.geoResults || []).find(g => g.ip === ip);
      nodes.push({ id: 'ip_' + ip, label: ip, type: 'ip', size: 14 });
      links.push({ source: 'email', target: 'ip_' + ip, label: 'Observable Hop IP', risk: geo?.risk || 'medium' });
    });

    // Domains
    const domains = [];
    if (this.result.domain?.domain && this.result.domain.domain !== 'Not available') {
      domains.push(this.result.domain.domain);
    }
    (this.result.urls || []).forEach(u => {
      const d = typeof u === 'string' ? u.replace(/^https?:\/\//, '').split('/')[0] : u.domain;
      if (d && !domains.includes(d) && domains.length < 3) domains.push(d);
    });

    domains.slice(0, 3).forEach((d) => {
      nodes.push({ id: 'domain_' + d, label: d.length > 25 ? d.slice(0, 22) + '...' : d, type: 'domain', size: 14 });
      links.push({ source: 'email', target: 'domain_' + d, label: 'Domain', risk: 'high' });
    });

    // Attachments
    const attachments = this.result.attachments || [];
    attachments.forEach((a, i) => {
      const name = a.filename || a.name || `Attachment ${i + 1}`;
      nodes.push({ id: 'attach_' + i, label: name.length > 20 ? name.slice(0, 17) + '...' : name, type: 'attachment', size: 14 });
      links.push({ source: 'email', target: 'attach_' + i, label: 'Attachment', risk: a.riskScore >= 60 ? 'critical' : a.riskScore >= 30 ? 'high' : 'low' });
    });

    this._render(nodes, links, container);
  }

  _render(nodes, links, container) {
    const w = this.width, h = this.height;
    const svg = d3.select(container).append('svg')
      .attr('width', '100%').attr('height', h)
      .attr('viewBox', `0 0 ${w} ${h}`)
      .style('background', 'transparent');

    // Defs for glow
    const defs = svg.append('defs');
    const filter = defs.append('filter').attr('id', 'glow');
    filter.append('feGaussianBlur').attr('stdDeviation', '3').attr('result', 'coloredBlur');
    const feMerge = filter.append('feMerge');
    feMerge.append('feMergeNode').attr('in', 'coloredBlur');
    feMerge.append('feMergeNode').attr('in', 'SourceGraphic');

    const colorMap = {
      email: '#00d4ff', sender: '#ff2d55', replyto: '#ff6b35',
      ip: '#7c3aed', domain: '#f59e0b', attachment: '#10b981'
    };
    const riskColor = { critical: '#ff2d55', high: '#ff6b35', medium: '#ffd60a', low: '#34d399', unknown: '#6b7280' };

    const simulation = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(links).id(d => d.id).distance(120).strength(0.5))
      .force('charge', d3.forceManyBody().strength(-300))
      .force('center', d3.forceCenter(w / 2, h / 2))
      .force('collision', d3.forceCollide().radius(d => d.size + 20));

    const link = svg.append('g').selectAll('line')
      .data(links).enter().append('line')
      .attr('stroke', d => riskColor[d.risk] || '#444')
      .attr('stroke-width', 1.5)
      .attr('stroke-opacity', 0.6)
      .attr('stroke-dasharray', d => d.risk === 'critical' ? '5,3' : 'none');

    const linkLabel = svg.append('g').selectAll('text')
      .data(links).enter().append('text')
      .attr('font-size', '9px').attr('fill', '#888')
      .attr('text-anchor', 'middle').text(d => d.label);

    const node = svg.append('g').selectAll('g')
      .data(nodes).enter().append('g')
      .call(d3.drag()
        .on('start', (event, d) => { if (!event.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
        .on('drag', (event, d) => { d.fx = event.x; d.fy = event.y; })
        .on('end', (event, d) => { if (!event.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; }));

    node.append('circle')
      .attr('r', d => d.size)
      .attr('fill', d => colorMap[d.type] + '33')
      .attr('stroke', d => colorMap[d.type])
      .attr('stroke-width', 2)
      .style('filter', 'url(#glow)');

    // Icon text in circle
    const iconMap = { email: '✉', sender: '👤', replyto: '↩', ip: '🌐', domain: '🔗', attachment: '📎' };
    node.append('text')
      .attr('text-anchor', 'middle').attr('dominant-baseline', 'central')
      .attr('font-size', d => d.size * 0.8 + 'px')
      .attr('fill', d => colorMap[d.type])
      .text(d => iconMap[d.type] || '●');

    node.append('text')
      .attr('y', d => d.size + 14)
      .attr('text-anchor', 'middle')
      .attr('font-size', '10px')
      .attr('fill', '#aaa')
      .text(d => d.label);

    simulation.on('tick', () => {
      link.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
          .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
      linkLabel.attr('x', d => (d.source.x + d.target.x) / 2)
               .attr('y', d => (d.source.y + d.target.y) / 2 - 4);
      node.attr('transform', d => `translate(${Math.max(30, Math.min(w-30, d.x))},${Math.max(30, Math.min(h-30, d.y))})`);
    });

    // Legend
    const legend = svg.append('g').attr('transform', `translate(10,10)`);
    const items = [['Email', '#00d4ff'],['Sender', '#ff2d55'],['IP Address', '#7c3aed'],['Domain', '#f59e0b'],['Attachment', '#10b981']];
    items.forEach(([label, color], i) => {
      const g = legend.append('g').attr('transform', `translate(0,${i*18})`);
      g.append('circle').attr('r', 5).attr('fill', color + '44').attr('stroke', color).attr('stroke-width', 1.5).attr('cx', 5).attr('cy', 0);
      g.append('text').attr('x', 14).attr('y', 4).attr('font-size', '10px').attr('fill', '#888').text(label);
    });
  }
}

window.ThreatGraph = ThreatGraph;
