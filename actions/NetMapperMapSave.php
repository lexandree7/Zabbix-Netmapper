<?php declare(strict_types = 0);


namespace Modules\NetMapper\Actions;

use API,
	Modules\NetMapper\Includes\BaseJsonController;

/**
 * Exports the current topology as a native Zabbix network map (Monitoring > Maps).
 */
class NetMapperMapSave extends BaseJsonController {

	private const MAX_ELEMENTS = 2000;

	// Icon name patterns of the default Zabbix image set, by node type.
	private const ICONS = [
		'switch' => ['/^Switch_\(64\)$/', '/switch/i'],
		'router' => ['/^Router_\(64\)$/', '/router/i'],
		'firewall' => ['/^Firewall_\(64\)$/', '/firewall|router/i'],
		'server' => ['/^Server_\(64\)$/', '/server/i'],
		'ap' => ['/^Network_\(64\)$/'],
		'plc' => ['/^Hub_\(64\)$/', '/^Network_\(64\)$/'],
		'hmi' => ['/^Workstation_\(64\)$/', '/workstation|computer/i'],
		'printer' => ['/^Printer_\(64\)$/', '/printer/i'],
		'default' => ['/^Network_\(64\)$/', '/network|cloud/i']
	];

	protected function getValidationRules(): array {
		return [
			'name' =>	'required|string|not_empty',
			'map' =>	'required|string|not_empty'
		];
	}

	protected function doAction(): void {
		$map = json_decode($this->getInput('map'), true);

		if (!is_array($map) || !isset($map['nodes'], $map['links']) || !is_array($map['nodes'])
				|| count($map['nodes']) > self::MAX_ELEMENTS) {
			$this->respondError(_('Invalid map data.'));

			return;
		}

		$icons = $this->resolveIcons();

		$min_x = $min_y = PHP_INT_MAX;
		$max_x = $max_y = PHP_INT_MIN;

		foreach ($map['nodes'] as $node) {
			$min_x = min($min_x, (int) ($node['x'] ?? 0));
			$min_y = min($min_y, (int) ($node['y'] ?? 0));
			$max_x = max($max_x, (int) ($node['x'] ?? 0));
			$max_y = max($max_y, (int) ($node['y'] ?? 0));
		}

		$margin = 80;
		$selements = [];
		$ids = [];
		$seq = 1;

		foreach ($map['nodes'] as $node) {
			if (!isset($node['id']) || !is_string($node['id'])) {
				continue;
			}

			$type = is_string($node['type'] ?? null) ? $node['type'] : 'default';
			$selement = [
				'selementid' => (string) $seq,
				'iconid_off' => $icons[$type] ?? $icons['default'],
				'x' => (int) ($node['x'] ?? 0) - $min_x + $margin,
				'y' => (int) ($node['y'] ?? 0) - $min_y + $margin,
				'label' => mb_substr((string) ($node['label'] ?? ''), 0, 255)
			];

			if (!empty($node['hostid']) && ctype_digit((string) $node['hostid'])) {
				$selement['elementtype'] = SYSMAP_ELEMENT_TYPE_HOST;
				$selement['elements'] = [['hostid' => (string) $node['hostid']]];
				$selement['label'] = "{HOST.NAME}\n{HOST.CONN}";
			}
			else {
				$selement['elementtype'] = SYSMAP_ELEMENT_TYPE_IMAGE;
			}

			$ids[$node['id']] = (string) $seq++;
			$selements[] = $selement;
		}

		$links = [];

		foreach ($map['links'] as $link) {
			if (!isset($link['a'], $link['b'], $ids[$link['a']], $ids[$link['b']])) {
				continue;
			}

			$label = trim(($link['a_port'] ?? '').' - '.($link['b_port'] ?? ''), ' -');

			$links[] = [
				'selementid1' => $ids[$link['a']],
				'selementid2' => $ids[$link['b']],
				'label' => mb_substr($label, 0, 255),
				'color' => (($link['protocol'] ?? '') === 'mac') ? '888888' : '00AA00'
			];
		}

		$result = API::Map()->create([[
			'name' => $this->getInput('name'),
			'width' => max(800, $max_x - $min_x + 2 * $margin),
			'height' => max(600, $max_y - $min_y + 2 * $margin),
			'label_type' => MAP_LABEL_TYPE_LABEL,
			'selements' => $selements,
			'links' => $links
		]]);

		if (!$result) {
			$messages = function_exists('get_and_clear_messages')
				? array_column(get_and_clear_messages(), 'message')
				: [];

			$this->respondError($messages ? implode(' ', $messages) : _('Cannot create map.'));

			return;
		}

		$this->respond(['sysmapid' => reset($result['sysmapids'])]);
	}

	private function resolveIcons(): array {
		$images = API::Image()->get([
			'output' => ['imageid', 'name'],
			'filter' => ['imagetype' => IMAGE_TYPE_ICON]
		]);

		if (!$images) {
			throw new \RuntimeException(_('No icon images found.'));
		}

		$icons = [];

		foreach (self::ICONS as $type => $patterns) {
			foreach ($patterns as $pattern) {
				foreach ($images as $image) {
					if (preg_match($pattern, $image['name'])) {
						$icons[$type] = $image['imageid'];
						break 2;
					}
				}
			}
		}

		$icons['default'] = $icons['default'] ?? $images[0]['imageid'];

		return $icons;
	}
}
