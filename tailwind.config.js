module.exports = {
  content: [
    "../public/**/*.html",
    "../public/js/**/*.js",
  ],
  theme: { extend: {} },
  plugins: [],
  safelist: [
    { pattern: /^(bg|text|border)-(red|green|blue|yellow|gray|slate|emerald|indigo|purple|orange)-(50|100|200|300|400|500|600|700|800|900)$/ },
    { pattern: /^(bg|text|border)-(white|black)$/ },
    { pattern: /^(p|px|py|pt|pr|pb|pl|m|mx|my|mt|mr|mb|ml)-(0|1|2|3|4|5|6|8|10|12|16|20|24)$/ },
    { pattern: /^(grid|col|row)-.+/ },
    { pattern: /^rounded(-(sm|md|lg|xl|2xl))?$/ },
    { pattern: /^shadow(-(sm|md|lg|xl|2xl))?$/ },
    { pattern: /^(w|h)-(full|screen|\d+|auto)$/ },
    { pattern: /^(flex|items|justify|content|self)-.+/ },
    { pattern: /^(hidden|block|inline|inline-block|table|table-row|table-cell)$/ },
  ],
};
