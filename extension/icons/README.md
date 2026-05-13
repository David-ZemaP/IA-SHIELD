# Iconos de la Extensión

Esta carpeta requiere tres archivos de icono en formato PNG para que la extensión funcione correctamente:

## Archivos requeridos:

1. **icon-16.png** - 16x16 pixels
2. **icon-48.png** - 48x48 pixels
3. **icon-128.png** - 128x128 pixels

## Cómo generar los iconos:

### Opción 1: Herramienta online
- Usar un generador de iconos como "Favicon.io" o "RealFaviconGenerator"
- Subir un logo de escudo (🛡️) o imagen de la app

### Opción 2: Crear manualmente
Puedes crear iconos simples con cualquier editor de imágenes (GIMP, Photoshop, Paint.NET, etc.):
- Crear una imagen con el color de fondo #1a1a2e
- Agregar un símbolo de escudo en blanco
- Exportar en los 3 tamaños

### Opción 3: CLI (ImageMagick)
```bash
convert -resize 16x16 shield.png icon-16.png
convert -resize 48x48 shield.png icon-48.png
convert -resize 128x128 shield.png icon-128.png
```

## Nota importante
Chrome requiere que los iconos sean archivos PNG válidos. Sin estos, la extensión mostrará errores al cargar. La extensión funcionará sin ellos, pero el ícono en la barra del navegador no se mostrará correctamente.