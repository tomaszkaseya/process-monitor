"""Entry point for the Process Monitor application."""

import sys


def main() -> None:
    try:
        import psutil  # noqa: F401
    except ImportError:
        print(
            "psutil is not installed. Run:  pip install psutil\n"
            "Then restart the application.",
            file=sys.stderr,
        )
        sys.exit(1)

    from process_monitor.app import App

    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
