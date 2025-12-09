# aiodukeenergy (OAuth Fix Fork)

[![License](https://img.shields.io/pypi/l/aiodukeenergy.svg?style=flat-square)](https://github.com/chrisduk112/aiodukeenergy/blob/main/LICENSE)

---

**This is a fork of [hunterjm/aiodukeenergy](https://github.com/hunterjm/aiodukeenergy) with fixes for the November 2025 Duke Energy OAuth migration.**

---

## What Changed

In November 2025, Duke Energy migrated to a new OpenID Connect / Auth0 authentication system. The original library's simple username/password authentication no longer works.

This fork implements:
- New OAuth 2.0 authentication flow with PKCE
- Updated client credentials from Duke Energy app v7.0
- New token exchange endpoint (`/login/auth-token`)
- Refresh token support

## Installation

### For Home Assistant Users

See the [Home Assistant Installation Guide](#home-assistant-installation) below.

### For Python Projects

Install directly from GitHub:

```bash
pip install git+https://github.com/chrisduk112/aiodukeenergy.git
```

## Usage

```python
import asyncio
import aiohttp
from aiodukeenergy import DukeEnergy

async def main():
    async with aiohttp.ClientSession() as session:
        client = DukeEnergy(
            username="your_email@example.com",
            password="your_password",
            session=session,
        )
        
        try:
            # Authenticate
            await client.authenticate()
            print(f"Authenticated as: {client.email}")
            
            # Get meters
            meters = await client.get_meters()
            for serial, meter in meters.items():
                print(f"Meter: {serial}")
                
        finally:
            await client.close()

asyncio.run(main())
```

## Home Assistant Installation

To use this fork with Home Assistant's Duke Energy integration:

### Method 1: Custom Components (Recommended)

1. **SSH into your Home Assistant** or use the File Editor add-on

2. **Navigate to your config directory**:
   ```bash
   cd /config
   ```

3. **Create custom_components directory** (if it doesn't exist):
   ```bash
   mkdir -p custom_components/duke_energy
   ```

4. **Copy the official integration files** and modify them to use this fork.

   Alternatively, use the pip override method below.

### Method 2: Override pip package

1. **SSH into your Home Assistant**

2. **Install this fork**:
   ```bash
   pip install git+https://github.com/chrisduk112/aiodukeenergy.git --upgrade
   ```

3. **Restart Home Assistant**

4. **Re-add the Duke Energy integration** from Settings → Devices & Services

**Note**: This method may need to be repeated after Home Assistant updates.

### Method 3: Using a requirements override (Advanced)

1. Create a file `/config/requirements_override.txt`:
   ```
   aiodukeenergy @ git+https://github.com/chrisduk112/aiodukeenergy.git
   ```

2. Add to your `configuration.yaml`:
   ```yaml
   homeassistant:
     packages: !include_dir_named packages
   ```

3. Restart Home Assistant

## Troubleshooting

### Authentication Errors

If you see `403 Forbidden` or `410 Gone` errors:
- Make sure you're using this fork, not the original library
- Verify your Duke Energy credentials work on their website
- Check Home Assistant logs for detailed error messages

### Enable Debug Logging

Add to `configuration.yaml`:
```yaml
logger:
  default: info
  logs:
    aiodukeenergy: debug
    homeassistant.components.duke_energy: debug
```

## Contributing

If you find issues or have improvements:
1. Fork this repository
2. Create a feature branch
3. Submit a pull request

## Credits

- Original library: [hunterjm/aiodukeenergy](https://github.com/hunterjm/aiodukeenergy)
- OAuth reverse engineering: Community members on [GitHub Issue #155863](https://github.com/home-assistant/core/issues/155863)

## License

MIT License - see [LICENSE](LICENSE) for details.
