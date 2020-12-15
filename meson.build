project('nss-database-pem-exporter', 'c',
    version: '0.1',
    license: 'GPLv3+',
    default_options: [
        'buildtype=debugoptimized',
        'warning_level=3',
        'c_std=gnu99',
    ],
    meson_version: '>= 0.50.0')


executable('nss-database-pem-exporter',
    sources: 'nss-database-pem-exporter.c',
    dependencies: dependency('nss'),
)
