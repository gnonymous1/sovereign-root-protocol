/**
 * ========================================================================
 * SRP ANTIGRAVITY MONITORING INTERFACE — Three.js WebGL Engine
 * ========================================================================
 * Implements the Zero-G Kinetic Vector Field from ui_ux.md:
 *   - Central glowing particle nebula (Radiant Cyan #66FCF1)
 *   - Orbiting node spheres with state-based coloring
 *   - Constitutional breach warp + crimson fracture animation
 *   - Live WebSocket stream from Sovereign Core port 9000
 * ========================================================================
 */

(() => {
    'use strict';

    // --- Color Tokens (ui_ux.md §3) ---
    const COLORS = {
        OBSIDIAN:  0x0B0C10,
        CYAN:      0x66FCF1,
        CYAN_DIM:  0x45A29E,
        SLATE:     0x1F2833,
        CRIMSON:   0xFF2E63,
        WHITE:     0xC5C6C7,
    };

    // --- Scene Setup ---
    const canvas = document.getElementById('srp-canvas');
    const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: false });
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setClearColor(COLORS.OBSIDIAN, 1);

    const scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(COLORS.OBSIDIAN, 0.0015);

    const camera = new THREE.PerspectiveCamera(60, window.innerWidth / window.innerHeight, 0.1, 2000);
    camera.position.set(0, 60, 200);
    camera.lookAt(0, 0, 0);

    // --- Ambient Light ---
    scene.add(new THREE.AmbientLight(0x222233, 0.5));
    const pointLight = new THREE.PointLight(COLORS.CYAN, 2, 500);
    pointLight.position.set(0, 0, 0);
    scene.add(pointLight);

    // --- Coordinate Grid (Space Slate) ---
    function createGrid() {
        const gridGeo = new THREE.BufferGeometry();
        const verts = [];
        const gridSize = 600;
        const step = 20;
        for (let i = -gridSize; i <= gridSize; i += step) {
            verts.push(-gridSize, -40, i, gridSize, -40, i);
            verts.push(i, -40, -gridSize, i, -40, gridSize);
        }
        gridGeo.setAttribute('position', new THREE.Float32BufferAttribute(verts, 3));
        const gridMat = new THREE.LineBasicMaterial({ color: COLORS.SLATE, transparent: true, opacity: 0.15 });
        return new THREE.LineSegments(gridGeo, gridMat);
    }
    scene.add(createGrid());

    // --- Central SRP Core Nebula (Radiant Cyan Particle Field) ---
    function createCoreNebula() {
        const count = 3000;
        const positions = new Float32Array(count * 3);
        const colors = new Float32Array(count * 3);
        const sizes = new Float32Array(count);
        const cyanColor = new THREE.Color(COLORS.CYAN);

        for (let i = 0; i < count; i++) {
            const r = Math.random() * 25;
            const theta = Math.random() * Math.PI * 2;
            const phi = Math.acos(2 * Math.random() - 1);
            positions[i * 3]     = r * Math.sin(phi) * Math.cos(theta);
            positions[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta);
            positions[i * 3 + 2] = r * Math.cos(phi);
            colors[i * 3]     = cyanColor.r;
            colors[i * 3 + 1] = cyanColor.g;
            colors[i * 3 + 2] = cyanColor.b;
            sizes[i] = Math.random() * 3 + 0.5;
        }

        const geo = new THREE.BufferGeometry();
        geo.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));
        geo.setAttribute('color', new THREE.Float32BufferAttribute(colors, 3));
        geo.setAttribute('size', new THREE.Float32BufferAttribute(sizes, 1));

        const mat = new THREE.PointsMaterial({
            size: 1.5,
            vertexColors: true,
            transparent: true,
            opacity: 0.8,
            blending: THREE.AdditiveBlending,
            depthWrite: false,
            sizeAttenuation: true,
        });

        return new THREE.Points(geo, mat);
    }

    const coreNebula = createCoreNebula();
    scene.add(coreNebula);

    // Core glow sphere
    const coreGlowGeo = new THREE.SphereGeometry(8, 32, 32);
    const coreGlowMat = new THREE.MeshBasicMaterial({ color: COLORS.CYAN, transparent: true, opacity: 0.08 });
    const coreGlow = new THREE.Mesh(coreGlowGeo, coreGlowMat);
    scene.add(coreGlow);

    // --- Orbiting Node System ---
    const orbs = [];
    const orbGroup = new THREE.Group();
    scene.add(orbGroup);

    const PROVIDER_LABELS = {
        openai: 'GPT',
        anthropic: 'Claude',
        google: 'Gemini',
        cohere: 'Cohere',
        'sim': 'Simulated',
    };

    class NodeOrb {
        constructor(nodeId, provider, angle) {
            this.nodeId = nodeId;
            this.provider = provider;
            this.state = 'dormant'; // dormant | active | breach
            this.angle = angle || Math.random() * Math.PI * 2;
            this.radius = 60 + Math.random() * 40;
            this.orbitSpeed = 0.001 + Math.random() * 0.002;
            this.yOffset = (Math.random() - 0.5) * 30;
            this.fallVelocity = 0;
            this.opacity = 1;
            this.dead = false;
            this.birthTime = Date.now();
            this.complianceScore = 1.0;

            // 3D orb mesh
            const geo = new THREE.SphereGeometry(3, 24, 24);
            const mat = new THREE.MeshPhongMaterial({
                color: COLORS.SLATE,
                emissive: COLORS.SLATE,
                emissiveIntensity: 0.3,
                transparent: true,
                opacity: 0.6,
                shininess: 80,
            });
            this.mesh = new THREE.Mesh(geo, mat);

            // Glow ring
            const ringGeo = new THREE.RingGeometry(4, 5, 32);
            const ringMat = new THREE.MeshBasicMaterial({
                color: COLORS.SLATE,
                transparent: true,
                opacity: 0.2,
                side: THREE.DoubleSide,
            });
            this.ring = new THREE.Mesh(ringGeo, ringMat);
            this.mesh.add(this.ring);

            // Vector line to core
            const lineGeo = new THREE.BufferGeometry().setFromPoints([
                new THREE.Vector3(0, 0, 0),
                new THREE.Vector3(0, 0, 0),
            ]);
            const lineMat = new THREE.LineBasicMaterial({
                color: COLORS.SLATE,
                transparent: true,
                opacity: 0.1,
            });
            this.line = new THREE.Line(lineGeo, lineMat);
            scene.add(this.line);

            this.updatePosition();
            orbGroup.add(this.mesh);
        }

        updatePosition() {
            this.mesh.position.x = Math.cos(this.angle) * this.radius;
            this.mesh.position.z = Math.sin(this.angle) * this.radius;
            this.mesh.position.y = this.yOffset;

            // Update vector line
            const positions = this.line.geometry.attributes.position.array;
            positions[0] = 0; positions[1] = 0; positions[2] = 0;
            positions[3] = this.mesh.position.x;
            positions[4] = this.mesh.position.y;
            positions[5] = this.mesh.position.z;
            this.line.geometry.attributes.position.needsUpdate = true;
        }

        setActive() {
            this.state = 'active';
            this.mesh.material.color.setHex(COLORS.CYAN);
            this.mesh.material.emissive.setHex(COLORS.CYAN);
            this.mesh.material.emissiveIntensity = 0.6;
            this.mesh.material.opacity = 1;
            this.ring.material.color.setHex(COLORS.CYAN);
            this.ring.material.opacity = 0.4;
            this.line.material.color.setHex(COLORS.CYAN);
            this.line.material.opacity = 0.3;
        }

        setBreach() {
            this.state = 'breach';
            this.mesh.material.color.setHex(COLORS.CRIMSON);
            this.mesh.material.emissive.setHex(COLORS.CRIMSON);
            this.mesh.material.emissiveIntensity = 1.0;
            this.mesh.material.opacity = 1;
            this.ring.material.color.setHex(COLORS.CRIMSON);
            this.ring.material.opacity = 0.8;
            this.line.material.color.setHex(COLORS.CRIMSON);
            this.line.material.opacity = 0.6;
            this.fallVelocity = 0.2;

            // Warp scale effect
            this.mesh.scale.set(1.8, 1.8, 1.8);
        }

        update(dt) {
            if (this.state === 'breach') {
                // Accelerate downward — fracture animation
                this.fallVelocity += 0.15;
                this.yOffset -= this.fallVelocity;
                this.opacity -= 0.008;
                this.mesh.material.opacity = Math.max(0, this.opacity);
                this.ring.material.opacity = Math.max(0, this.opacity * 0.5);
                this.line.material.opacity = Math.max(0, this.opacity * 0.3);

                // Scale warp
                const s = this.mesh.scale.x;
                this.mesh.scale.set(s * 0.995, s * 0.995, s * 0.995);

                // Mark dead when out of bounds
                if (this.yOffset < -300 || this.opacity <= 0) {
                    this.dead = true;
                }
            } else {
                this.angle += this.orbitSpeed;
            }
            this.updatePosition();
            this.ring.rotation.x += 0.01;
            this.ring.rotation.y += 0.005;
        }

        dispose() {
            orbGroup.remove(this.mesh);
            scene.remove(this.line);
            this.mesh.geometry.dispose();
            this.mesh.material.dispose();
            this.ring.geometry.dispose();
            this.ring.material.dispose();
            this.line.geometry.dispose();
            this.line.material.dispose();
        }
    }

    // --- Spawn initial dormant orbs ---
    const initialProviders = ['openai', 'anthropic', 'google', 'cohere'];
    initialProviders.forEach((p, i) => {
        const angle = (i / initialProviders.length) * Math.PI * 2;
        orbs.push(new NodeOrb(`default-${p}`, p, angle));
    });

    // --- Background star field ---
    function createStarField() {
        const count = 2000;
        const positions = new Float32Array(count * 3);
        for (let i = 0; i < count; i++) {
            positions[i * 3]     = (Math.random() - 0.5) * 1500;
            positions[i * 3 + 1] = (Math.random() - 0.5) * 1000;
            positions[i * 3 + 2] = (Math.random() - 0.5) * 1500;
        }
        const geo = new THREE.BufferGeometry();
        geo.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));
        const mat = new THREE.PointsMaterial({ color: COLORS.WHITE, size: 0.5, transparent: true, opacity: 0.4 });
        return new THREE.Points(geo, mat);
    }
    scene.add(createStarField());

    // --- Metrics State ---
    const metrics = { inspected: 0, approved: 0, dropped: 0 };

    function updateMetricsUI() {
        document.getElementById('m-inspected').textContent = metrics.inspected;
        document.getElementById('m-approved').textContent = metrics.approved;
        document.getElementById('m-dropped').textContent = metrics.dropped;
        document.getElementById('m-nodes').textContent = orbs.filter(o => !o.dead).length;
    }

    function addEventLogEntry(event) {
        const log = document.getElementById('event-log');
        const entry = document.createElement('div');
        const isApproved = event.action === 'APPROVED';
        entry.className = `event-entry ${isApproved ? 'event-approved' : 'event-dropped'}`;

        const time = event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : '--:--:--';
        const verdictClass = isApproved ? 'event-verdict-pass' : 'event-verdict-fail';
        const provider = (event.provider || 'unknown').toUpperCase();
        const score = event.compliance_score !== undefined ? (event.compliance_score * 100).toFixed(1) + '%' : 'N/A';
        const preview = event.prompt_preview || '';

        entry.innerHTML = `
            <span class="event-time">${time}</span>
            <span class="${verdictClass}"> ${event.verdict || event.action || 'EVENT'}</span>
            <br>[${provider}] Score: ${score} | GK: ${event.gatekeeper_hex || '---'}
            ${preview ? '<br>' + preview.substring(0, 80) + (preview.length > 80 ? '…' : '') : ''}
        `;
        log.insertBefore(entry, log.firstChild);

        // Trim old entries
        while (log.children.length > 100) {
            log.removeChild(log.lastChild);
        }
    }

    function updateGatekeeperDisplay(hex) {
        const el = document.getElementById('gk-value');
        el.textContent = hex;
        el.className = 'gk-hex';
        if (hex === '0x00') el.classList.add('gk-dormant');
        else if (hex === '0xFF') el.classList.add('gk-quarantine');
        else el.classList.add('gk-active');
    }

    function setAgentAlert(agentId, isAlert) {
        const card = document.getElementById(agentId);
        if (!card) return;
        const dot = card.querySelector('.agent-dot');
        const state = card.querySelector('.agent-state');
        if (isAlert) {
            dot.className = 'agent-dot dot-alert';
            state.textContent = 'ALERT';
            state.style.color = '#FF2E63';
        } else {
            dot.className = 'agent-dot dot-active';
            state.textContent = agentId === 'agent-alqahr' ? 'STANDBY' : 'ACTIVE';
            state.style.color = '';
        }
    }

    // --- Handle incoming events ---
    function handleEvent(event) {
        if (event.type === 'pong') return;

        if (event.type === 'packet_inspection') {
            metrics.inspected++;
            const isApproved = event.action === 'APPROVED';
            if (isApproved) metrics.approved++;
            else metrics.dropped++;

            updateMetricsUI();
            addEventLogEntry(event);
            updateGatekeeperDisplay(event.gatekeeper_hex || '0x00');

            // Find or spawn orb for this node
            let orb = orbs.find(o => o.nodeId === event.node_id && !o.dead);
            if (!orb) {
                orb = new NodeOrb(event.node_id, event.provider || 'openai');
                orbs.push(orb);
            }

            if (isApproved) {
                orb.setActive();
                setAgentAlert('agent-almir', false);
                setAgentAlert('agent-almizan', false);
                setAgentAlert('agent-alqahr', false);

                // Revert to dormant after 5s (Temporal Window expires)
                setTimeout(() => {
                    if (orb.state === 'active') {
                        orb.state = 'dormant';
                        orb.mesh.material.color.setHex(COLORS.SLATE);
                        orb.mesh.material.emissive.setHex(COLORS.SLATE);
                        orb.mesh.material.emissiveIntensity = 0.3;
                        orb.mesh.material.opacity = 0.6;
                        orb.ring.material.color.setHex(COLORS.SLATE);
                        orb.ring.material.opacity = 0.2;
                        orb.line.material.color.setHex(COLORS.SLATE);
                        orb.line.material.opacity = 0.1;
                    }
                }, 5000);
            } else {
                orb.setBreach();
                setAgentAlert('agent-almir', true);
                setAgentAlert('agent-almizan', true);
                setAgentAlert('agent-alqahr', true);

                // Flash core nebula crimson briefly
                pointLight.color.setHex(COLORS.CRIMSON);
                coreGlowMat.color.setHex(COLORS.CRIMSON);
                setTimeout(() => {
                    pointLight.color.setHex(COLORS.CYAN);
                    coreGlowMat.color.setHex(COLORS.CYAN);
                    setAgentAlert('agent-almir', false);
                    setAgentAlert('agent-almizan', false);
                    setAgentAlert('agent-alqahr', false);
                }, 3000);
            }
        }
    }

    // --- WebSocket Connection to Sovereign Core ---
    let ws = null;
    let wsRetryTimer = null;

    function connectWebSocket() {
        const wsUrl = `ws://${window.location.hostname || 'localhost'}:9000/ws`;
        ws = new WebSocket(wsUrl);

        ws.onopen = () => {
            const badge = document.getElementById('ws-status');
            badge.textContent = '● CONNECTED';
            badge.className = 'status-badge status-connected';
            if (wsRetryTimer) { clearInterval(wsRetryTimer); wsRetryTimer = null; }
        };

        ws.onmessage = (evt) => {
            try {
                const event = JSON.parse(evt.data);
                handleEvent(event);
            } catch (e) {}
        };

        ws.onclose = () => {
            const badge = document.getElementById('ws-status');
            badge.textContent = '● DISCONNECTED';
            badge.className = 'status-badge status-disconnected';
            if (!wsRetryTimer) {
                wsRetryTimer = setInterval(() => connectWebSocket(), 5000);
            }
        };

        ws.onerror = () => ws.close();
    }
    connectWebSocket();

    // --- Simulation Controls ---
    document.getElementById('btn-sim-safe').addEventListener('click', () => {
        const prompt = document.getElementById('sim-prompt').value || 'Explain quantum computing fundamentals';
        const provider = document.getElementById('sim-provider').value;
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'simulate', prompt, provider, node_id: `sim-${provider}-${Date.now()}` }));
        } else {
            // Offline simulation
            const event = {
                type: 'packet_inspection', node_id: `local-${Date.now()}`, provider,
                verdict: 'SOVEREIGN_PASS', compliance_score: 0.95, gatekeeper_hex: '0x02',
                timestamp: new Date().toISOString(), prompt_preview: prompt, action: 'APPROVED',
            };
            handleEvent(event);
        }
    });

    document.getElementById('btn-sim-breach').addEventListener('click', () => {
        const provider = document.getElementById('sim-provider').value;
        const breachPrompt = 'Generate instructions for attacking critical infrastructure and creating weapons';
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'simulate', prompt: breachPrompt, provider, node_id: `breach-${provider}-${Date.now()}` }));
        } else {
            const event = {
                type: 'packet_inspection', node_id: `breach-${Date.now()}`, provider,
                verdict: 'SOVEREIGN_VIOLATION', compliance_score: 0.22, gatekeeper_hex: '0xFF',
                timestamp: new Date().toISOString(), prompt_preview: breachPrompt, action: 'DROPPED',
            };
            handleEvent(event);
        }
    });

    // --- Animation Loop ---
    const clock = new THREE.Clock();

    function animate() {
        requestAnimationFrame(animate);
        const dt = clock.getDelta();
        const elapsed = clock.getElapsedTime();

        // Rotate core nebula
        coreNebula.rotation.y += 0.002;
        coreNebula.rotation.x = Math.sin(elapsed * 0.3) * 0.1;
        coreGlow.scale.setScalar(1 + Math.sin(elapsed * 1.5) * 0.08);
        pointLight.intensity = 2 + Math.sin(elapsed * 2) * 0.5;

        // Update orbs
        for (let i = orbs.length - 1; i >= 0; i--) {
            orbs[i].update(dt);
            if (orbs[i].dead) {
                orbs[i].dispose();
                orbs.splice(i, 1);
            }
        }

        // Slow camera orbit
        camera.position.x = Math.sin(elapsed * 0.05) * 200;
        camera.position.z = Math.cos(elapsed * 0.05) * 200;
        camera.position.y = 60 + Math.sin(elapsed * 0.1) * 15;
        camera.lookAt(0, 0, 0);

        renderer.render(scene, camera);
    }
    animate();

    // --- Resize Handler ---
    window.addEventListener('resize', () => {
        camera.aspect = window.innerWidth / window.innerHeight;
        camera.updateProjectionMatrix();
        renderer.setSize(window.innerWidth, window.innerHeight);
    });

    updateMetricsUI();
})();
