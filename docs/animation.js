const canvas = document.getElementById('frog-canvas');
const ctx = canvas.getContext('2d');

const PIXEL_SIZE = 8;
const WIDTH = canvas.width;
const HEIGHT = canvas.height;

// Colors
const COLOR_BG = 'rgba(0,0,0,0)'; // Transparent
const COLOR_FROG = '#22c55e'; // Green
const COLOR_FROG_DARK = '#166534';
const COLOR_EYE = '#ffffff';
const COLOR_PUPIL = '#000000';
const COLOR_TONGUE = '#ef4444'; // Red
const COLOR_FLY = '#ffffff';
const COLOR_RADAR = 'rgba(14, 165, 233, 0.4)'; // Cyan
const COLOR_RADAR_LINE = '#0ea5e9';

// Frog Sprite (10x9)
const frogSpriteIdle = [
    "  █████   ",
    " ███████  ",
    "█e█d█e█d█ ",
    "█████████ ",
    " ███████  ",
    "█████████ ",
    "██ ███ ██ ",
    "█   █   █ ",
    "██     ██ "
];

const frogSpriteOpen = [
    "  █████   ",
    " ███████  ",
    "█e█d█e█d█ ",
    "█████████ ",
    " █     █  ",
    "█████████ ",
    "██ ███ ██ ",
    "█   █   █ ",
    "██     ██ "
];

let frame = 0;
let flyX = 50;
let flyY = 200;
let flyAlive = true;
let state = 'IDLE'; // IDLE, SHOOTING, RETRACTING
let tongueLength = 0;
let idleTimer = 0;
let radarY = HEIGHT;

function drawPixel(x, y, color) {
    ctx.fillStyle = color;
    ctx.fillRect(x * PIXEL_SIZE, y * PIXEL_SIZE, PIXEL_SIZE, PIXEL_SIZE);
}

function drawSprite(sprite, startX, startY) {
    for (let r = 0; r < sprite.length; r++) {
        for (let c = 0; c < sprite[r].length; c++) {
            const char = sprite[r][c];
            if (char === '█') drawPixel(startX + c, startY + r, COLOR_FROG);
            else if (char === 'd') drawPixel(startX + c, startY + r, COLOR_FROG_DARK);
            else if (char === 'e') drawPixel(startX + c, startY + r, COLOR_EYE);
            else if (char === 'o') drawPixel(startX + c, startY + r, COLOR_PUPIL);
        }
    }
}

function updateRadar() {
    radarY -= 2;
    if (radarY < 0) {
        radarY = HEIGHT;
    }
}

function drawRadar() {
    // Floor
    ctx.fillStyle = '#1e293b';
    ctx.fillRect(0, HEIGHT - 40, WIDTH, 40);

    // Radar Line
    ctx.fillStyle = COLOR_RADAR_LINE;
    ctx.fillRect(0, radarY, WIDTH, 2);

    // Radar Glow
    const gradient = ctx.createLinearGradient(0, radarY, 0, radarY + 50);
    gradient.addColorStop(0, COLOR_RADAR);
    gradient.addColorStop(1, 'rgba(14, 165, 233, 0)');
    ctx.fillStyle = gradient;
    ctx.fillRect(0, radarY + 2, WIDTH, 50);
}

function drawFly(x, y) {
    if (!flyAlive) return;
    drawPixel(x, y, COLOR_FLY);
    drawPixel(x + 1, y, COLOR_FLY);
    drawPixel(x, y + 1, COLOR_FLY);
    drawPixel(x + 1, y + 1, COLOR_FLY);
    
    // Wings flapping
    if (frame % 10 < 5) {
        drawPixel(x - 1, y - 1, COLOR_FLY);
        drawPixel(x + 2, y - 1, COLOR_FLY);
    } else {
        drawPixel(x - 1, y, COLOR_FLY);
        drawPixel(x + 2, y, COLOR_FLY);
    }
}

function update() {
    frame++;

    updateRadar();

    const frogGridX = 35;
    const frogGridY = (HEIGHT - 40) / PIXEL_SIZE - 9; // sit on floor
    const mouthGridY = frogGridY + 4;
    const mouthGridX = frogGridX;

    if (state === 'IDLE') {
        idleTimer++;
        
        // Fly hovering
        if (flyAlive) {
            flyX = 10 + Math.sin(frame * 0.05) * 5;
            flyY = 20 + Math.cos(frame * 0.03) * 5;
        }

        if (idleTimer > 150 && flyAlive) {
            state = 'SHOOTING';
            idleTimer = 0;
        }
        
        if (!flyAlive && idleTimer > 100) {
            flyAlive = true; // respawn
        }
    } else if (state === 'SHOOTING') {
        tongueLength += 2;
        
        // Check collision (tongue extends leftwards from frog)
        const currentTongueTip = mouthGridX - tongueLength;
        if (currentTongueTip <= flyX + 2) {
            state = 'RETRACTING';
        }
    } else if (state === 'RETRACTING') {
        tongueLength -= 2;
        flyX = mouthGridX - tongueLength; // fly moves with tongue

        if (tongueLength <= 0) {
            state = 'IDLE';
            flyAlive = false;
        }
    }

    // DRAW
    ctx.clearRect(0, 0, WIDTH, HEIGHT);
    
    drawRadar();
    drawFly(flyX, flyY);

    if (state === 'IDLE') {
        drawSprite(frogSpriteIdle, frogGridX, frogGridY);
    } else {
        drawSprite(frogSpriteOpen, frogGridX, frogGridY);
        // Draw tongue
        ctx.fillStyle = COLOR_TONGUE;
        ctx.fillRect((mouthGridX - tongueLength) * PIXEL_SIZE, mouthGridY * PIXEL_SIZE, tongueLength * PIXEL_SIZE, PIXEL_SIZE);
    }
}

// Loop
setInterval(update, 1000 / 60);
