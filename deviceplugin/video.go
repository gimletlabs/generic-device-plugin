// Copyright 2023 the generic-device-plugin authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package deviceplugin

import (
	"crypto/sha1"
	"fmt"
	"io/fs"
	"path"
	"strconv"
	"strings"
	"unsafe"

	"github.com/go-kit/kit/log/level"
	"golang.org/x/sys/unix"
	"k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"
)

const (
	videoDevicesDir = "/dev/"

	VIDIOC_QUERYCAP = 0x80685600
	VIDIOC_G_FMT    = 0xC0D05604

	V4L2_CAP_VIDEO_CAPTURE = 0x00000001

	V4L2_BUF_TYPE_VIDEO_CAPTURE = 1

	PIX_FMT_YUYV = 'Y' | 'U'<<8 | 'Y'<<16 | 'V'<<24
	PIX_FMT_MJPG = 'M' | 'J'<<8 | 'P'<<16 | 'G'<<24
)

type v4l2_capability struct {
	driver       [16]uint8
	card         [32]uint8
	bus_info     [32]uint8
	version      uint32
	capabilities uint32
	device_caps  uint32
	reserved     [3]uint32
}

type v4l2_format struct {
	buf_type uint32
	_        uint32 // padding
	data     [200]byte
}

type v4l2_pix_format struct {
	width          uint32
	height         uint32
	pix_format     uint32
	field          uint32
	bytes_per_line uint32
	size_image     uint32
	color_space    uint32
	priv           uint32
	flags          uint32
	ycbcr_enc      uint32
	quantization   uint32
	xfer_func      uint32
}

// videoDevice represents a video capture device.
type videoDevice struct {
	path string
}

// ioctl system call for device control
func ioctl(fd int, req uint, arg unsafe.Pointer) error {
	if _, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(req),
		uintptr(arg),
	); errno != 0 {
		return errno
	}
	return nil
}

// enumerateVideoDevices rapidly scans the OS system bus for attached Video devices.
// Pure Go; does not require external linking.
func (gp *GenericPlugin) enumerateVideoDevices(fsys fs.FS, dir string) ([]videoDevice, error) {
	var outDevs []videoDevice
	allDevs, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, err
	}
	for _, dev := range allDevs {
		if dev.IsDir() {
			continue
		}
		if !strings.HasPrefix(dev.Name(), "video") {
			continue
		}
		devPath := path.Join(videoDevicesDir, dev.Name())
		fd, err := unix.Open(devPath, unix.O_RDONLY, 0666)
		if nil != err {
			level.Warn(gp.logger).Log("msg", fmt.Sprintf("Couldn't open device %s", devPath))
			continue
		}
		capability := v4l2_capability{}
		ioctl(fd, VIDIOC_QUERYCAP, unsafe.Pointer(&capability))
		if capability.device_caps&V4L2_CAP_VIDEO_CAPTURE == 0 {
			level.Debug(gp.logger).Log("msg", fmt.Sprintf("Device doesn't have V4L2_CAP_VIDEO_CAPTURE %s", devPath))
			continue
		}

		format := v4l2_format{}
		format.buf_type = V4L2_BUF_TYPE_VIDEO_CAPTURE
		ioctl(fd, VIDIOC_G_FMT, unsafe.Pointer(&format))
		pixFormat := (*v4l2_pix_format)(unsafe.Pointer(&format.data[0]))
		if pixFormat.pix_format != PIX_FMT_YUYV && pixFormat.pix_format != PIX_FMT_MJPG {
			level.Debug(gp.logger).Log("msg", fmt.Sprintf("Device doesn't have PIX_FMT_YUYV or PIX_FMT_MJPG %s", devPath))
			continue
		}

		outDevs = append(outDevs, videoDevice{
			path: devPath,
		})
	}
	level.Debug(gp.logger).Log("msg", fmt.Sprintf("Got %d video devices", len(outDevs)))
	return outDevs, nil
}

func (gp *GenericPlugin) discoverVideo() ([]device, error) {
	videoDevs, err := gp.enumerateVideoDevices(gp.fs, videoDevicesDir)
	if err != nil {
		return nil, err
	}
	if len(videoDevs) == 0 {
		return []device{}, nil
	}
	var devices []device

	for _, group := range gp.ds.Groups {
		if group.Video && len(videoDevs) > 0 {
			for _, dev := range videoDevs {
				for j := uint(0); j < group.Count; j++ {
					h := sha1.New()
					h.Write([]byte(strconv.FormatUint(uint64(j), 10)))
					d := device{
						Device: v1beta1.Device{
							Health: v1beta1.Healthy,
						},
					}

					d.deviceSpecs = append(d.deviceSpecs, &v1beta1.DeviceSpec{
						HostPath:      dev.path,
						ContainerPath: dev.path,
						Permissions:   "rw",
					})
					h.Write([]byte(dev.path))
					d.ID = fmt.Sprintf("%x", h.Sum(nil))
					devices = append(devices, d)
				}
			}
		}
	}
	return devices, nil
}
