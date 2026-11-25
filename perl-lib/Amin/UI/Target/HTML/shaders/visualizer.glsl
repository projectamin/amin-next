precision mediump float;
uniform vec2 u_res;
uniform float u_time;
uniform float u_energy;
uniform float u_mode;
uniform vec3 u_bg;
uniform vec3 u_lo;
uniform vec3 u_sig;
uniform vec3 u_hi;

float hash(vec2 p) {
    return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453123);
}

void main() {
    vec2 uv = gl_FragCoord.xy / u_res;
    vec2 p = uv * 2.0 - 1.0;
    p.x = p.x * u_res.x / max(u_res.y, 1.0);
    float t = u_time;
    float v = 0.0;
    if (u_mode > 1.5) {
        float r = length(p) + 0.001;
        float a = atan(p.y, p.x);
        v = sin(a * 2.0 + r * 8.0 - t * 0.8 + u_energy * 4.0) * 0.72
          + sin(r * 17.0 - t * 1.7 - u_energy * 6.0) * 0.28;
    } else if (u_mode > 0.5) {
        float r = length(p);
        v = sin(r * 9.0 - t * 1.6 - u_energy * 5.0) * 0.8
          + sin(r * 21.0 - t * 2.9) * 0.2;
    } else {
        v = sin(p.x * 2.4 + t * 0.55)
          + sin(p.y * 3.0 - t * 0.42)
          + sin((p.x + p.y) * 1.7 + t * 0.73 + u_energy * 2.0)
          + sin(length(p) * 3.2 - t * 0.9) * 0.6;
        v = v * 0.29;
    }
    float band = smoothstep(-0.3, 1.0, v);
    float glow = smoothstep(0.55, 1.0, band);
    vec3 col = mix(u_bg, u_lo, band * 0.5);
    col = mix(col, u_sig, glow * (0.36 + 0.55 * u_energy));
    col = mix(col, u_hi, smoothstep(0.88, 1.0, band) * 0.35);
    float g = hash(gl_FragCoord.xy + vec2(t * 7.0, t * 3.0));
    gl_FragColor = vec4(col + (g - 0.5) * 0.018, 1.0);
}
